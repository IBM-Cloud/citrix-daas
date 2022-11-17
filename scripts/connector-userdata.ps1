#ps1_sysnative

#############################################################################
# © Copyright IBM Corp. 2021, 2021

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#############################################################################

<#
.SYNOPSIS
    Installs and congifures Cloud Connector.

.DESCRIPTION
    This script installs the Cloud Connector and IBM Cloud VPC Plugin, joins the Active Directory domain
    and registers with Citrix Cloud.

.NOTES
    This script is executed post server deployment by Cloudbase-Init when using the IBM Cloud topology.
    For Extended topology this script must be run manually, specifying the parameters below, after running
    the ad-extended.ps1 script on the Active Directory server.
#>

param (
    # Cloud Connector join password for Active Directory
    [string]
    $ConnectorJoinPassword,

    #Citrix Cloud client secret needed to access Citrix API
    [string]
    $CitrixClientSecret,

    # GitHub personal access token needed to download plugin msi from private repository during Beta
    [string]
    $GitHubPersonalAccessToken
)

#
# Include Common PS
#
${common_ps}

Function Create-Script {
    <#
    .SYNOPSIS
        Copies script to directory.

    .DESCRIPTION
        This function copies this script to the C drive to be run manually when using Extended topology.
    #>
    Copy-Item "$($MyInvocation.ScriptName)" -Destination "C:\ConnectorSetup.ps1"
    Write-Log -Level Info "C:\ConnectorSetup.ps1 has been successfully created. Run ConnectorSetup.ps1 with arguments after AD setup is complete."
}

Function Join-ComputerToActiveDirectory {
    <#
    .SYNOPSIS
        Joins Active Directory Domain.

    .DESCRIPTION
        This function sets the preferred DNS to the Active Directory IP address and joins the domain.
    #>
    Write-Log -Level Info "ad name is ${ad_domain_name}"
    Write-Log -Level Info "ad ip is ${ad_ip}"

    if ((Get-WmiObject Win32_ComputerSystem).Domain -eq "${ad_domain_name}") {
        Write-Log -Level Info "Already Joined to the Domain ${ad_domain_name}"
        return $false
    }

    Set-Dns ${ad_ip}
    Write-Log -Level Info "Disabling ad join password change in registry settings."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "DisablePasswordChange" -Value 1

    # Join domain with retries
    Write-Log -Level Info "Starting to join domain"
    $UntilDone = $false

    if ("${topology}" -eq "Extended") {
        Write-Log -Level Info "Will wait indefinitely for Active Directory to be setup"
        $UntilDone = $true
    }

    Retry-Command -ScriptBlock {
        $joinCred = New-Object pscredential -ArgumentList ([pscustomobject]@{
            UserName = $null
            Password = (ConvertTo-SecureString -String $JoinPassword -AsPlainText -Force)[0]
        })
        $AddComputer = Add-Computer -Domain ${ad_domain_name} -Options UnsecuredJoin,PasswordPass -Credential $joinCred -ErrorAction Stop -Verbose
        Write-Log -Level Info "Added Computer $AddComputer"
    } -Attempts 25 -UntilDone $UntilDone
    return $true
}

Function DownloadCloudConnector {
    <#
    .SYNOPSIS
        Downloads Cloud Connector software.

    .DESCRIPTION
        This function downloads the Cloud Connector software from Citrix.
    #>
    $downloadPath = $env:SystemDrive + "\"
    $exeName = "cwcconnector.exe"
    $downloadsUri = New-Object -TypeName System.Uri `
        -ArgumentList "https://downloads.cloud.com/${customer_id}/connector/$exeName"
    $downloadPath = (Join-Path -Path $downloadPath -ChildPath $exeName)
    Write-Log -Level Info "Downloading $downloadsUri to $downloadPath"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    try {
        Invoke-WebRequest -Method GET -Uri $downloadsUri -OutFile $downloadPath -Verbose

        if (Test-Path $downloadPath) {
            Write-Log -Level Info "Connector downloaded successfully from $downloadsUri to $downloadPath"
            Write-FileVersion -FilePath $env:SystemDrive -FileName $exeName
            return $downloadPath
        }

        $message = "Unable to download connector from $downloadsUri to $downloadPath"
    } catch [System.Net.WebException] {
        $message = "Unable to download connector: $_"
    }

    Write-Log -Level Error $message
    Throw $message
}

Function Get-ResourceLocationId {
    <#
    .SYNOPSIS
        Gets Citrix Resource Location ID.

    .DESCRIPTION
        This function uses the Citrix rest API to get the Citrix Resource Location ID for the specified
        resource location name.
    #>
    try {
        $url = "https://registry.citrixworkspacesapi.net/${customer_id}/resourcelocations"
        $response = Invoke-RestMethod -Method GET `
            -Uri $(New-Object -TypeName System.Uri -ArgumentList $url) `
            -Headers $(Get-BearerAuthHeader $configuration) `
            -ContentType "application/json" `
            -Verbose
        $location = $response.items | Where-Object {$_.name -eq "${resource_location_name}"}
        Write-Log -Level Info "Get-ResourceLocationId $($location.id) Count: $($response.items.Count)"
        return $location.id
    }
    catch [System.Net.WebException] {
        Write-Log -Level Error "Get-ResourceLocationId failed: $_.Exception.Message"
        throw $_
    }
}

Function Register-CloudConnector {
    <#
    .SYNOPSIS
        Registers Cloud Connector.

    .DESCRIPTION
        This function runs the Cloud Connector software which registers the Cloud Connector with
        Citrix Cloud.

    .PARAMETER $FilePath
        The file path of the Cloud Connector executable.

    .PARAMETER $ResourceLocationId
        The Citrix Resource Location ID that will be associated with the Cloud Connector.
    #>
    [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string]
            $FilePath,

            [Parameter(Mandatory = $true)]
            [string]
            $ResourceLocationId
        )

    Write-Log -Level Info "** Running... $FilePath ."

    $arguments = @(
        "/q",
        "/Customer:${customer_id}",
        "/ClientId:${api_id}",
        "/ClientSecret:$ClientSecret",
        "/ResourceLocationId:$($ResourceLocationId)",
        "/AcceptTermsOfService:true"
    )

    $process = Start-Process $FilePath $arguments -Wait -Passthru
    $Logs1 = "%ProgramData%\Citrix\WorkspaceCloud\InstallLogs"
    $Logs2 = "%LOCALAPPDATA%\Temp\CitrixLogs\CloudServicesSetup"
    $LogInfo = "Please check installation logs at $Logs1 or $Logs2. For more information visit: https://docs.citrix.com/en-us/citrix-cloud/citrix-cloud-resource-locations/citrix-cloud-connector/installation.html#troubleshooting-installation-issues"

    if ($process.ExitCode -eq 0) {
        Write-Log -Level Info "$FilePath Installation Complete"
    } elseIf ($process.ExitCode -eq 1603) {
        if (Test-RebootRequired) {
            Write-Log -Level Info "$FilePath Installation failed since a reboot is required."
            # reboot and rerun this script
            exit 1003
        }
        throw "An unexpected error occured while installing $FilePath. Exit code: $($process.ExitCode). " + $LogInfo
    } elseIf ($process.ExitCode -eq 2) {
        Write-Log -Level Info "A prerequisite check failed while installing $FilePath. Exit code: $($process.ExitCode). " + $LogInfo
    } else {
        Write-Log -Level Error "Unable to Install $FilePath.  Exit code: $($process.ExitCode). " + $LogInfo
    }
}

Function Download-Plugin {
    <#
    .SYNOPSIS
        Downloads and installs IBMCloud VPC Plugin.

    .DESCRIPTION
        This function downloads and installs the IBM Cloud VPC Plugin to enable Web Studio functionality
        in Citrix Cloud.
    #>

    $tag = "${tag}"

    $latest = "IBM-CitrixDaaS-$tag"
    $downloadsUri = New-Object -TypeName System.Uri `
        -ArgumentList "${repository_download_url}/zipball/$tag"
    $downloadPath = Join-Path -Path $pluginDir -ChildPath "$latest.zip"
    $unzipPath = Join-Path -Path $pluginDir -ChildPath $latest
    New-Item -ItemType Directory -Force -Path "$pluginDir"

    try {
        Write-Log -Level Info "Downloading $downloadsUri to $downloadPath"

        if ($PersonalAccessToken -eq "" -Or $downloadsUri -like "https://api.github.com/repos/IBM-Cloud/citrix-daas*") {
            Invoke-WebRequest -Method GET -Uri $downloadsUri -OutFile $downloadPath -Verbose
        } else {
            Invoke-WebRequest -Method GET -Headers @{Authorization = "token $PersonalAccessToken"} `
            -Uri $downloadsUri -OutFile $downloadPath -Verbose
        }

        if (Test-Path $downloadPath) {
            Write-Log -Level Info "Plugin downloaded successfully from $downloadsUri to $downloadPath"
        } else {
            $message = "Unable to download plugin from $downloadsUri to $downloadPath"
        }

        Write-Log -Level Info "Expanding $downloadPath"
        Expand-Archive $downloadPath -DestinationPath $unzipPath -Force
        $result = Get-ChildItem -path $unzipPath
        $dir = Join-Path -Path $unzipPath -ChildPath $result
        $msi = "IBM-CitrixDaaS-plugin.msi"

        # Extract plugin msi
        Move-Item "$dir\$msi" -Destination "$pluginDir\$msi" -Force

        $PluginVersion = Get-MSIProductVersion -MSIPATH "$pluginDir\$msi"
        Write-Log -Level Info "$msi plugin product version is $PluginVersion"

        # Cleanup zipball and uncompressed dir
        Remove-Item $downloadPath -Recurse -Force
        Remove-Item $unzipPath -Recurse -Force

        Write-Log -Level Info "Installing plugin"

        $MSIArguments = @(
                    "/i"
                    ('"{0}"' -f "$pluginDir\$msi")
                    "/q"
                    "/L*v"
                    (Get-LogPath) + "\PluginMSI.log"
                )

        $process = Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -Passthru

        if ($process.ExitCode -eq 0) {
            Write-Log -Level Info "msi Installation Complete"
            Write-FileVersion -FilePath "$pluginDir" -FileName "IBMVPCSupportService.exe"
            Write-FileVersion -FilePath "$pluginDir" -FileName "IBM.Cloud.VPC.Provisioning.dll"
        } elseIf ($process.ExitCode -eq 1603) {
            Write-Log -Level Info "An unexpected error occured while installing msi. Exit code: $($process.ExitCode)"
        } elseIf ($process.ExitCode -eq 2) {
            Write-Log -Level Info "A prerequiste check failed while installing msi. Exit code: $($process.ExitCode)"
        } else {
            Write-Log -Level Error "Unable to Install msi.  Exit code: $($process.ExitCode)"
        }

        return $true
    } catch [System.Net.WebException] {
        $message = "Unable to download plugin $_"
    }

    Write-Log -Level Error $message
    Throw $message
}

Function Register-Plugin {
    <#
    .SYNOPSIS
        Registers IBM Cloud VPC Plugin.

    .DESCRIPTION
        This function runs the plugin registration executable which registers the IBM Cloud VPC Plugin
        with Citrix Cloud.
    #>
    pushd "$citrixPluginsDir"

    Retry-Command -ScriptBlock {
        Write-Log -Level Info "$(dir | Out-String)"
        if ([System.IO.File]::Exists("$citrixPluginsDir\RegisterPlugins.exe")) {
            Write-FileVersion -FilePath "$citrixPluginsDir" -FileName "RegisterPlugins.exe"
        }
        $result = .\RegisterPlugins.exe -PluginsRoot "$citrixPluginsRoot" | Out-String
        $registrationExitCode = $LASTEXITCODE
        Write-Log -Level Info "RegisterPlugins output: $result"
        if ($registrationExitCode -eq 0) {
            Write-Log -Level Info "Plugin Registration Complete"
        } else {
            Write-Log -Level Error "Unable to Register $citrixPluginsRoot.  Exit code: $registrationExitCode"
        }
    }
    popd
}

Function Set-Registry {
    <#
    .SYNOPSIS
        Sets Windows Registry keys.

    .DESCRIPTION
        The IBM Cloud VPC Plugin needs information about the Citrix DaaS deployment. This function sets necessary
        keys in the Windows Registry.
    #>

    try {
        Write-Log -Level Info "Writing registry."

        $registryKeys = @{
            Region = "${region}";
            ConnectorVpcId = "${vpc_id}";
            ResourceGroupId = "${resource_group_id}";
            AccountId = "${ibmcloud_account_id}";
            ZoneName = "${zone}";
            PreparationSecurityGroupName = "${master_prep_sg}";
            CatalogDefaultSecurityGroupName = "${vda_sg}";
            COSBucketName = "${cos_bucket_name}";
            COSRegionName = "${cos_region_name}";
            DedicatedHostGroupId = "${dedicated_host_group_id}";
            IdentityVolumeEncryptionCrn = "${identity_volume_encryption_crn}"
        }

        $path = "HKLM:\Software\IBM\CitrixDaaS"
        New-Item $path -Force

        foreach ($registryKey in $registryKeys.GetEnumerator()) {
            Set-ItemProperty -Path $path -Name $registryKey.Name -Value $registryKey.Value
        }

        $DwordRegistryKeys = @{}

        if (${use_volume_worker}) {
            $DwordRegistryKeys.Add("UseVolumeWorker", 1)
        }

        foreach ($registryKey in $DwordRegistryKeys.GetEnumerator()) {
            Set-ItemProperty -Path $path -Name $registryKey.Name -Value $registryKey.Value -Type DWord
        }

    }
    catch {
        Write-Log -Level Error "Set-Registry failed: $_"
        throw $_
    }
}

Function Disable-ieESC {
    <#
    .SYNOPSIS
        Disables Internet Explorer security.

    .DESCRIPTION
        This function disables Internet Explorer security to open internet egress.
    #>
    Write-Log -Level Info "Entering Disable-ieESC"
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
    Write-Log -Level Info "IE Enhanced Security Configuration (ESC) has been disabled."
}

Function Test-CitrixAgentHub {
    <#
    .SYNOPSIS
        Tests Citrix Agent Hub.

    .DESCRIPTION
        This function pings the Citrix Agent Hub to test for a successful response.
    #>
    try {
        $apiurl = "https://agenthub.citrixworkspacesapi.net/root/ping"
        $apiping = Invoke-WebRequest $apiurl -UseBasicParsing -Verbose
        Write-Log -Level Info "Citrix Workspace Ping Response for $apiurl : $($apiping.StatusDescription) ($($apiping.StatusCode))"
    } catch {
        Write-Log -Level Error $_
    }
}

Function Add-TrustedSites {
    <#
    .SYNOPSIS
        Adds trusted sites.

    .DESCRIPTION
        This function adds a list of trusted sites keys to the domains path in the Windows Registry.
    #>
    $TrustedSites = @(
        "*.citrixworkspacesapi.net",
        "*.citrixnetworkapi.net",
        "*.cloud.com",
        "*.blob.core.windows.net",
        "*.nssvc.net",
        "*.servicebus.windows.net",
        "*.xendesktop.net",
        "*.citrixdata.com",
        "*.sharefile.com",
        "*.digicert.com",
        "*.azureedge.net",
        "login.citrixonline.com"
    )

    Write-Log -Level Info "Now configuring IE Trusted Sites"

    try {
        ForEach ($TrustedSite in $TrustedSites) {
            $location = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains"
            set-location $location
            $regKeyPath = "$location\$TrustedSite"

            if (!(Test-Path $regKeyPath)) {
                new-item $TrustedSite/ -Force
                set-location $TrustedSite/
                new-itemproperty . -Name https -Value 2 -Type DWORD -Force
                Write-Log -Level Info "Added Trusted Site $TrustedSite to the Registry"
            } else {
                Write-Log -Level Info "Already added Trusted Site $TrustedSite"
            }
        }
    } catch {
        Write-Log -Level Info "Cannot add TrustedSites to the Registry $_"
    }

    Write-Log -Level Info "Finished adding Trusted Sites"
}

Function Get-BearerAuthHeader {
    <#
    .SYNOPSIS
        Gets Bearer Token.

    .DESCRIPTION
        This function gets a bearer token to authenticate with the Citrix Cloud API.
    #>
    try {
        $response = Invoke-RestMethod -Uri "https://trust.citrixworkspacesapi.net/root/tokens/clients" `
            -Method "Post" `
            -Body (ConvertTo-Json @{clientId = "${api_id}"; clientSecret = "$ClientSecret"}) `
            -ContentType application/json -TimeoutSec 300  -Verbose
        Write-Log -Level Info "Get-BearerAuthHeader complete"
        return @{"Authorization" = "CWSAuth bearer=`"$($response.token)`""}
    } catch [System.Net.WebException] {
        Write-Log -Level Error "Get-BearerAuthHeader failed: $_.Exception.Message"
        throw $_
    }
}

Function Test-IsServiceInstalled {
    <#
    .SYNOPSIS
        Tests Citrix service install.

    .DESCRIPTION
        This functions tests if the Citrix Cloud Services AD Provider is installed.
    #>
    if ("$(Get-Service $citrixServiceName -ErrorAction SilentlyContinue)" -eq "") {
        Write-Log -Level Info "$citrixServiceName not installed"
        return $false
    } else {
        return $true
    }
}

Function Test-IsServiceRunning {
    <#
    .SYNOPSIS
        Tests Citrix service is running.

    .DESCRIPTION
        This functions tests if the Citrix Cloud Services AD Provider is running.
    #>
    if (!(Test-IsServiceInstalled)) {
        return $false
    }

    $status = (Get-Service $citrixServiceName).Status
    Write-Log -Level Info "$citrixServiceName status: $status"

    if ($status -eq "Running") {
        return $true
    } else {
        return $false
    }
}

Function Get-MSIProductVersion {
    <#
    .SYNOPSIS
        Get the MSI Product Version.

    .DESCRIPTION
        This functions returns the Product Version of an MSI file by querying the MSI database.
    #>
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
            [System.IO.FileInfo] $MSIPATH
    )
    if (!(Test-Path $MSIPATH.FullName)) {
        throw "File '{0}' does not exist" -f $MSIPATH.FullName
    }
    try {
        $WindowsInstaller = New-Object -com WindowsInstaller.Installer
        $Database = $WindowsInstaller.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $Null, $WindowsInstaller, @($MSIPATH.FullName, 0))
        $Query = "SELECT Value FROM Property WHERE Property = 'ProductVersion'"
        $View = $database.GetType().InvokeMember("OpenView", "InvokeMethod", $Null, $Database, ($Query))
        $View.GetType().InvokeMember("Execute", "InvokeMethod", $Null, $View, $Null) | Out-Null
        $Record = $View.GetType().InvokeMember( "Fetch", "InvokeMethod", $Null, $View, $Null )
        $Version = $Record.GetType().InvokeMember( "StringData", "GetProperty", $Null, $Record, 1 )
        return $Version
    } catch {
        throw "Failed to get MSI file version: {0}." -f $_
    }
}

Function Write-FileVersion {
    <#
    .SYNOPSIS
        Writes the File Version to the Log file.
    #>
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
            [System.IO.FileInfo] $FilePath,

        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
            [System.IO.FileInfo] $FileName
    )

    $FileVersion = (Get-Item "$FilePath\$FileName").VersionInfo.FileVersion
    Write-Log -Level Info "$FileName file version is $FileVersion"
}

#
# MAIN
#
$citrixPluginsDir = "C:\Program Files\Common Files\Citrix\HCLPlugins"
$citrixPluginsRoot = "$citrixPluginsDir\CitrixMachineCreation\v1.0.0.0"
$pluginDir = "$citrixPluginsRoot\IBMCloud"
# Last service installed
$citrixServiceName = "Citrix ClxMtp Service"

if ("${topology}" -eq "Extended") {
    Write-Log -Level Info "Active Directory topology is set to Extended."

    if ($ConnectorJoinPassword -eq "") {
        Write-Log -Level Info "Manual AD setup required for Extended topology. Creating ConnectorSetup.ps1 in C:\"
        Create-Script
        exit 0
    }

    $JoinPassword = $ConnectorJoinPassword
    $ClientSecret = $CitrixClientSecret
    $PersonalAccessToken = $GitHubPersonalAccessToken
} else {
    Write-Log -Level Info "Active Directory topology is set to IBM Cloud."
    $JoinPassword = "${ad_join_pwd}"
    $ClientSecret = "${api_secret}"
    $PersonalAccessToken = "${ghe_token}"
}

try {
    Write-Log -Level Info "Active Directory topology is ${topology}"
    Write-Environment
    Disable-ieESC
    Add-TrustedSites
    Test-CitrixAgentHub

    $ResourceLocationId = Get-ResourceLocationId

    Set-Registry
    Write-Log -Level Info "Set registry complete"

    if (!(Test-IsServiceInstalled)) {
        $FilePath = DownloadCloudConnector
    }

    $domainJoined = Join-ComputerToActiveDirectory

    if (!(Test-IsServiceInstalled)) {
        Register-CloudConnector $FilePath $ResourceLocationId
    }

    Download-Plugin

    # Check if Citrix service running
    Write-Log -Level Info "Checking if Citrix Service running"

    Retry-Command -ScriptBlock {
        if (!(Test-IsServiceRunning)) {
            throw "Citrix Service not running"
        }
    } -Attempts 20

    Write-Log -Level Info "Citrix Service is running"
    Register-Plugin
    Write-Log -Level Info "Registration Complete"
    Write-Log -Level Info "Restart and do not run this script (1001)"
    exit 1001
} catch {
    Write-Log -Level Error "Connector setup failed: $_"
    exit 1
}
