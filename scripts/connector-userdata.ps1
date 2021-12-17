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

param (
[string]$ConnectorJoinPassword,
[string]$CitrixClientSecret,
[string]$GitHubPersonalAccessToken
)
Function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Error","Warn","Info")][string]$Level
    )
    $LevelValue = @{Error='Error'; Warn='Warning'; Info='Information'}[$Level]
    $LogFile = $env:SystemDrive + "\IBMCVADInstallation.log"
    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    Add-Content $LogFile -Value "$Stamp $LevelValue $Message"
}
Function Write-Environment {
    Write-Log -Level Info "----------------------------------------"
    Write-Log -Level Info "Started executing $($MyInvocation.ScriptName)"
    Write-Log -Level Info "----------------------------------------"
    Write-Log -Level Info "Script Version: 2021.10.05-1"
    Write-Log -Level Info "Current User: $env:username"
    Write-Log -Level Info "Hostname: $env:computername"
    Write-Log -Level Info "The OS Version is $env:OSVersion.Version"
    Write-Log -Level Info "Host Version $($Host.Version)"
    $DotNet = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
    Write-Log -Level Info ".NET version/release $($DotNet.version)/$($DotNet.release)"
}
Function Create-Script {
    Copy-Item "$($MyInvocation.ScriptName)" -Destination "C:\ConnectorSetup.ps1"
    Write-Log -Level Info "C:\ConnectorSetup.ps1 has been successfully created. Run ConnectorSetup.ps1 with arguments after AD setup is complete."
}
Function Join-ComputerToActiveDirectory {
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
    } -Attempts 20 -UntilDone $UntilDone
    return $true
}
Function Set-Dns {
    [CmdletBinding()]param([Parameter(Mandatory=$true)][string]$PreferredDnsServer)
    
    $Interface = Get-WmiObject Win32_NetworkAdapterConfiguration
    $dnsServers = $Interface | Select-Object -ExpandProperty DNSServerSearchOrder
    Write-Log -Level Info "Initial DNS Search Order: $dnsServers"
    if ($Interface.DNSServerSearchOrder.contains($PreferredDnsServer)) {
        Write-Log -Level Info "Dns is already set to $PreferredDnsServer"
        return
    }

    if ([bool]($PreferredDnsServer -as [ipaddress])) {
        Write-Log -Level Info "Registering DNS $PreferredDnsServer"
        $result = $Interface.SetDNSServerSearchOrder($PreferredDnsServer)
        Write-Log -Level Info "DNS Registered Result: $result"
        $dnsServers = $Interface | Select-Object -ExpandProperty DNSServerSearchOrder
        Write-Log -Level Info "Modified DNS Search Order: $dnsServers"
    } else {
        Write-Log -Level Error "Incorrect Preferred Dns Server $PreferredDnsServer"
        exit 1
    }
}
Function DownloadCloudConnector {
    $downloadPath = $env:SystemDrive + '\'
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
    [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)][string]$exePath,
            [Parameter(Mandatory=$true)][string]$resourceLocationId
        )
    Write-Log -Level Info "** Running... $exePath ."
    $arguments = @(
        "/q",
        "/Customer:${customer_id}",
        "/ClientId:${api_id}",
        "/ClientSecret:$ClientSecret",
        "/ResourceLocationId:$($resourceLocationId)",
        "/AcceptTermsOfService:true"
    )
    $process = Start-Process $exePath $arguments -Wait -Passthru
    if ($process.ExitCode -eq 0) {
        Write-Log -Level Info "$exePath Installation Complete"
    } elseIf ($process.ExitCode -eq 1603) {
        Write-Log -Level Info "An unexpected error occured while installing $exePath. Exit code: $($process.ExitCode)"
    } elseIf ($process.ExitCode -eq 2) {
        Write-Log -Level Info "A prerequiste check failed while installing $exePath. Exit code: $($process.ExitCode)"
    } else {
        Write-Log -Level Error "Unable to Install $exePath.  Exit code: $($process.ExitCode)"
    }
}
Function Download-Plugin {
    if ("${dev_mode}" -eq $false) {
        $repo = "citrix-virtual-apps-and-desktops"
        $baseUri = "https://api.github.com/repos/IBM-Cloud/$repo"
    } else {
        $repo = "cvad-vpc-tf"
        $baseUri = "https://api.github.ibm.com/repos/workload-eng-services/$repo"
    }
    $releasesUri = New-Object -TypeName System.Uri `
        -ArgumentList "$baseUri/releases"
    $tag = ""
    if ("${ghe_token}" -eq "") {
        $tag = (Invoke-WebRequest -Method GET -UseBasicParsing -Uri $releasesUri | ConvertFrom-Json)[0].tag_name
    } else {
        $tag = (Invoke-WebRequest -Method GET -UseBasicParsing -Headers @{Authorization = "token $PersonalAccessToken"} `
        -Uri $releasesUri | ConvertFrom-Json)[0].tag_name
    }

    $latest = "$repo-$tag"
    $downloadsUri = New-Object -TypeName System.Uri `
        -ArgumentList "$baseUri/zipball/$tag"
    $downloadPath = Join-Path -Path $pluginDir -ChildPath "$latest.zip"
    $unzipPath = Join-Path -Path $pluginDir -ChildPath $latest
    New-Item -ItemType Directory -Force -Path "$pluginDir"
    try {
        Write-Log -Level Info "Downloading $downloadsUri to $downloadPath"
        if ($PersonalAccessToken -eq "") {
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
        $msi = "cvad-plugin.msi"

        # Extract plugin msi
        Move-Item "$dir\$msi" -Destination "$pluginDir\$msi" -Force

        # Cleanup zipball and uncompressed dir
        Remove-Item $downloadPath -Recurse -Force
        Remove-Item $unzipPath -Recurse -Force

        Write-Log -Level Info "Installing plugin"
        $MSIArguments = @(
                    "/i"
                    ('"{0}"' -f "$pluginDir\$msi")
                    "/q"
                    "/L*v"
                    "C:\msi.log"
                )
        $process = Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -Passthru
        if ($process.ExitCode -eq 0) {
            Write-Log -Level Info "msi Installation Complete"
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
    pushd "$citrixPluginsDir"

    Retry-Command -ScriptBlock {
        Write-Log -Level Info "$(dir | Out-String)"
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
    Write-Log -Level Info "Writing registry."
    $registryKeys = @{
        Region = "${region}";
        ConnectorVpcId = "${vpc_id}";
        ResourceGroupId = "${resource_group_id}";
        AccountId = "${ibmcloud_account_id}";
        ZoneName = "${zone}";
        PreparationSecurityGroupName = "${master_prep_sg}";
        CatalogDefaultSecurityGroupName = "vda-sg";
    }
    New-Item 'HKLM:\Software\IBM\CVAD' -Force
    foreach ($registryKey in $registryKeys.GetEnumerator()) {
        Set-ItemProperty -Path 'HKLM:\Software\IBM\CVAD' -Name $registryKey.Name -Value $registryKey.Value
    }
}
Function Disable-ieESC {
    Write-Log -Level Info "Entering Disable-ieESC"
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
    Write-Log -Level Info "IE Enhanced Security Configuration (ESC) has been disabled."
}
Function Test-CitrixAgentHub {
    try {
        $apiurl = "https://agenthub.citrixworkspacesapi.net/root/ping"
        $apiping = Invoke-WebRequest $apiurl -UseBasicParsing -Verbose
        Write-Log -Level Info "Citrix Workspace Ping Response for $apiurl : $($apiping.StatusDescription) ($($apiping.StatusCode))"
    } catch {
        Write-Log -Level Error $_
    }
}
Function Add-TrustedSites {
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
    c:
}
Function Get-BearerAuthHeader {
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
    if ("$(Get-Service $citrixServiceName -ErrorAction SilentlyContinue)" -eq "") {
        Write-Log -Level Info "$citrixServiceName not installed"
        return $false
    } else {
        return $true
    }
}
Function Test-IsServiceRunning {
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

function Retry-Command {
    [CmdletBinding()]
    Param(
        [Parameter(Position=0, Mandatory=$true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Position=1, Mandatory=$false)]
        [int]$Attempts = 5,

        [Parameter(Position=2, Mandatory=$false)]
        [int]$Delay = 60,

        [Parameter(Position=3, Mandatory=$false)]
        [bool]$UntilDone = $false
    )

    Begin {
        $count = 0
    }
    Process {
        do {
            $count++
            try {
                $ScriptBlock.Invoke()
                return
            } catch {
                Write-Log -Level Info $_.Exception.InnerException.Message -ErrorAction Continue
                Start-Sleep -Seconds $Delay
            }
        } while (($count -lt $Attempts) -or ($UntilDone))

        throw "Failed to execute retry block after $Attempts attempts"
    }
}

#
# MAIN
#
$citrixPluginsDir = "C:\Program Files\Common Files\Citrix\HCLPlugins"
$citrixPluginsRoot = "$citrixPluginsDir\CitrixMachineCreation\v1.0.0.0"
$pluginDir = "$citrixPluginsRoot\IBMCloud"
$citrixServiceName = "Citrix Cloud Services AD Provider"
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
    Write-Log -Level Info "CVAD topology is ${topology}"
    Write-Environment
    Disable-ieESC
    Add-TrustedSites
    Test-CitrixAgentHub
    $resourceLocationId = Get-ResourceLocationId
    if (!(Test-IsServiceInstalled)) {
        $exePath = DownloadCloudConnector
    }
    $domainJoined = Join-ComputerToActiveDirectory
    if (!(Test-IsServiceInstalled)) {
        Register-CloudConnector $exePath $resourceLocationId
    }
    Download-Plugin
    # Check if Citrix service running
    Write-Log -Level Info "Checking if Citrix Service running"
    Retry-Command -ScriptBlock {
        if (!(Test-IsServiceRunning)) {
            throw "Citrix Service not running"
        }
    }
    Write-Log -Level Info "Citrix Service is running"
    Register-Plugin
    Write-Log -Level Info "Registration Complete"
    Set-Registry $registryKeys
    Write-Log -Level Info "Set registy complete"
    Write-Log -Level Info "Restart and do not run this script (1001)"
    exit 1001
} catch {
    Write-Log -Level Error "Connector setup failed: $_"
    exit 1
}
