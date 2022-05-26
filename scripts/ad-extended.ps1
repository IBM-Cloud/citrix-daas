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
    Installs extended Active Directory domain controller.

.DESCRIPTION
    This script installs and configures an extended Active Directory domain controller, and joins the 
    domain controller to the root Active Directory domain. The parameters below must be supplied when
    running this script to join the root Active Directory domain and pre-register the Cloud Connector(s).

.NOTES
    This script needs to be run manually on all Active Directory servers when using Extended topology.
    Cloudbase-Init will save this script at C:\ActiveDirectorySetup.ps1 when the virtual server is
    deployed. This script must be run before the connector-userdata.ps1 script on the Cloud Connector
    server(s)
#>

param (
    # Username for joining Active Directory Domain
    [string]
    $Username,

    # Password for joining Active Directory Domain
    [string]
    $Password,

    # Join password to set for pre-registering Cloud Connectors to join Active Directory Domain
    [string]
    $ConnectorJoinPassword,

    # IP Address of root Active Directory Domain Controller
    [string]
    $RootActiveDirectoryIPAddress,

    # FQDN of root Active Directory Domain Controller
    [string]
    $ReplicationSourceDC,

    # Password to set for DSRM on Active Directory Domain Controller
    [string]
    $ActiveDirectorySafeModePassword
)

Function Write-Log {
    <#
    .SYNOPSIS
        Writes log message to log file.

    .DESCRIPTION
        This function accepts a log message and optional log level,
        then adds a timestamped log message to the log file.

    .PARAMETER $Message
        Message string that will be added to the log file.

    .PARAMETER $Level
        Optional log level parameter that must be "Error", "Warn", or "Info".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Error", "Warn", "Info")]
        [string]
        $Level
    )

    $LevelValue = @{Error = "Error"; Warn = "Warning"; Info = "Information"}[$Level]
    $LogFile = $env:SystemDrive + "\IBMCVADInstallation.log"
    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    Add-Content $LogFile -Value "$Stamp $LevelValue $Message"
}

Function Write-Environment {
    <#
    .SYNOPSIS
        Writes header to the log file.

    .DESCRIPTION
        This function writes a header to the log file to capture general information about the
        script execution environment.
    #>
    Write-Log -Level Info "----------------------------------------"
    Write-Log -Level Info "Started executing $($MyInvocation.ScriptName)"
    Write-Log -Level Info "----------------------------------------"
    Write-Log -Level Info "Script Version: 2022.02.07-1"
    Write-Log -Level Info "Current User: $env:username"
    Write-Log -Level Info "Hostname: $env:computername"
    Write-Log -Level Info "The OS Version is $((Get-CimInstance Win32_OperatingSystem).version)"
    Write-Log -Level Info "Host Version $($Host.Version)"
    $DotNet = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
    Write-Log -Level Info ".NET version/release $($DotNet.version)/$($DotNet.release)"
}

Function Retry-Command {
    <#
    .SYNOPSIS
        Retries script block.

    .DESCRIPTION
        This function accepts a script block and retries x number of times with a specified delay
        between attempts.

    .PARAMETER $ScriptBlock
        Script block to execute retries on.

    .PARAMETER $Attempts
        Number of attempts to try before erroring out.

    .PARAMETER $Delay
        Delay in seconds between attempts.

    .PARAMETER $UntilDone
        Can set to true to stop retries.

    #>
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [scriptblock]
        $ScriptBlock,

        [Parameter(Position = 1, Mandatory = $false)]
        [int]
        $Attempts = 5,

        [Parameter(Position = 2, Mandatory = $false)]
        [int]
        $Delay = 60,

        [Parameter(Position = 3, Mandatory = $false)]
        [bool]
        $UntilDone = $false
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

Function Create-Script {
    <#
    .SYNOPSIS
        Copies script to directory.

    .DESCRIPTION
        This function copies this script to the C drive to be run manually when using Extended topology.
    #>
    Copy-Item "$($MyInvocation.ScriptName)" -Destination "C:\ActiveDirectorySetup.ps1"
    Write-Log -Level Info "C:\ActiveDirectorySetup.ps1 has been successfully created. Run ActiveDirectorySetup.ps1 with arguments to complete setup."
}

Function Custom-InstallADDomainController {
    <#
    .SYNOPSIS
        Installs Active Directory Domain Controller.

    .DESCRIPTION
        This function installs the Active Directory Domain Controller given credential and domain
        information input.

    .PARAMETER $SiteName
        Active Directory Site to associate with Domain Controller.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $SiteName
    )

    $Password = ConvertTo-SecureString -String $Password -AsPlainText -Force
    $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username,$Password

    $result = Install-ADDSDomainController `
                -SafeModeAdministratorPassword (ConvertTo-SecureString -String $ActiveDirectorySafeModePassword -AsPlainText -Force) `
                -NoGlobalCatalog:$false `
                -CreateDnsDelegation:$false `
                -DomainName ${ad_domain_name} `
                -Credential $Credentials `
                -CriticalReplicationOnly:$false `
                -DatabasePath "C:\Windows\NTDS" `
                -InstallDns:$true `
                -LogPath "C:\Windows\NTDS" `
                -NoRebootOnCompletion:$false `
                -ReplicationSourceDC $ReplicationSourceDC `
                -SiteName $SiteName `
                -SysvolPath "C:\Windows\SYSVOL" `
                -Force:$true

    if ($?) {
        return $result
    }

    throw $result.Message
}

Function Set-Dns {
    <#
    .SYNOPSIS
        Sets preferred DNS.

    .DESCRIPTION
        This function sets the preferred IP address for DNS.

    .PARAMETER $PrefferedDNSServer
        IP Address to set as preferred DNS address.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $PreferredDnsServer
    )

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

Function Run-Install {
    <#
    .SYNOPSIS
        Installs Active Directory.

    .DESCRIPTION
        This function installs Active Directory if not already installed and sets up the Domain Controller.
    #>
    if (Check-Install -eq $true) {
        Write-Log -Level Info "ActiveDirectory is installed"
        (Get-Service ADWS).WaitForStatus("Running", $(New-TimeSpan -seconds 30))
        Write-Log -Level Info "Setting alternate DNS for root AD to put in $RootActiveDirectoryIPAddress"
        $Interface = Get-DnsClientServerAddress | Select-Object InterfaceIndex, ServerAddresses
        Set-DnsClientServerAddress -InterfaceIndex $Interface[0].InterfaceIndex -ServerAddresses "127.0.0.1",$RootActiveDirectoryIPAddress

        $configuration = @{
            connectorHosts = [System.Collections.ArrayList]@()
        }

        $zones = "${zones}"
        $AdZones = $zones.Split(",")
        $connectorCount = ${connector_reg_num} * $AdZones.count
        Write-Log -Level Info "Adding connector hostnames to register list."

        for ($i = 1; $i -le $connectorCount; $i++) {
            try {
                Get-ADComputer -Identity "${connector_name}-${resource_identifier}-$i" | Out-Null
            } catch {
                $configuration["connectorHosts"].Add("${connector_name}-${resource_identifier}-$i")
            }
        }

        if ($($configuration["connectorHosts"].count) -gt 0) {
            $joinPassword = (ConvertTo-SecureString -String $ConnectorJoinPassword -AsPlainText -Force)
            Write-Log -Level Info "ADWS status: $((Get-Service ADWS).Status)"
            Write-Log -Level Info "Registering connector hostnames: $($configuration["connectorHosts"])"

            foreach ($hostname in $configuration["connectorHosts"]) {
                New-ADComputer -Name $hostname -AccountPassword $joinPassword
            }

            Write-Log -Level Info "Connector hostnames registration complete."
        } else {
            Write-Log -Level Info "Connector hostnames registration list is empty, all connectors registered"
        }

        Write-Log -Level Info "Enabling SMB2 protocol."
        Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
        Write-Log -Level Info "Run-Install Complete. Service: $(Get-ADDomainController -Discover -Service ADWS)"
        exit 0
    }

    Write-Log -Level Info "Synchronizing Time with SL servers"
    w32tm /config /manualpeerlist:servertime.service.softlayer.com /syncfromflags:MANUAL
    Stop-Service w32time
    Start-Service w32time
    Write-Log -Level Info "Wait for w32time to start"
    (Get-Service w32time).WaitForStatus("Running", $(New-TimeSpan -seconds 15))
    Write-Log -Level Info "Adding RSAT-Role-Tools"
    Add-WindowsFeature RSAT-Role-Tools
    Write-Log -Level Info "Adding AD-Domain-Services"
    Add-WindowsFeature AD-Domain-Services

    try {
        Write-Log -Level Info "Setting DNS to primary active directory $RootActiveDirectoryIPAddress"
        Set-Dns $RootActiveDirectoryIPAddress
        Import-Module ADDSDeployment
        Write-Log -Level Info "Site Name is Default-First-Site-Name, Root AD Domain Controller is $ReplicationSourceDC"

        Retry-Command -ScriptBlock {
            $result = Custom-InstallADDomainController -SiteName "Default-First-Site-Name"
            Write-Log -Level Info "ActiveDirectory domain controller: $($result.Message)"
        } -Attempts 15
        return $true
    } catch {
        Write-Log -Level Error "Run-Install failed: $_"
        return $false
    }
}

Function Check-Install {
    <#
    .SYNOPSIS
        Checks Active Directory install.

    .DESCRIPTION
        This function verifies that Active Directory is installed by getting the Active Directory
        Domain Controller.
    #>
    if ((Get-Module -ListAvailable | where { $_.Name -eq "ActiveDirectory" }) -eq $null) {
        return $false
    }

    try {
        Get-ADDomainController
        return $true
    } catch {
        return $false
    }
}

#
# MAIN
#
Write-Environment
Write-Log -Level Info "CVAD topology is ${topology}"

if ($RootActiveDirectoryIPAddress -eq "") {
    Write-Log -Level Info "Manual AD setup required for Extended topology. Creating ActiveDirectorySetup.ps1 in C:\"
    Create-Script
    exit 0
}

$activeDirectoryInstalled = Run-Install
Write-Log -Level Info "Active Directory setup complete ($activeDirectoryInstalled) "

if ($activeDirectoryInstalled) {
        Write-Log -Level Info "Active Directory Installed - Please run this script again after restart completes (1001)"
exit 1001
}
exit 0
