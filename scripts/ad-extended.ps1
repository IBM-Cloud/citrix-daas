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
[string]$Username,
[string]$Password,
[string]$ConnectorJoinPassword,
[string]$RootActiveDirectoryIPAddress,
[string]$ReplicationSourceDC,
[string]$ActiveDirectorySafeModePassword
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
Function Retry-Command {
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
Function Create-Script {
    Copy-Item "$($MyInvocation.ScriptName)" -Destination "C:\ActiveDirectorySetup.ps1"
    Write-Log -Level Info "C:\ActiveDirectorySetup.ps1 has been successfully created. Run ActiveDirectorySetup.ps1 with arguments to complete setup."
}
Function Custom-InstallADDomainController {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$SiteName
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
Function Run-Install {
    if (Check-Install -eq $true) {
        Write-Log -Level Info "ActiveDirectory is installed"
        (Get-Service ADWS).WaitForStatus('Running', $(New-TimeSpan -seconds 30))
        Write-Log -Level Info "Setting alternate DNS for root AD to put in $RootActiveDirectoryIPAddress"
        $Interface = Get-DnsClientServerAddress | Select-Object InterfaceIndex, ServerAddresses
        Set-DnsClientServerAddress -InterfaceIndex $Interface[0].InterfaceIndex -ServerAddresses "127.0.0.1",$RootActiveDirectoryIPAddress
        $configuration = @{
            connectorHosts = [System.Collections.ArrayList]@()
        }
        for ($i = 1; $i -le ${connector_depth}; $i++) {
            $configuration['connectorHosts'].Add("${connector_name}-${resource_identifier}-$i")
        }
        Write-Log -Level Info "ADWS: $((Get-Service ADWS).Status) Hostnames: $($configuration['connectorHosts'])"
        $joinPassword = (ConvertTo-SecureString -String $ConnectorJoinPassword -AsPlainText -Force)
        foreach ($hostname in $configuration['connectorHosts']) {
            Write-Log -Level Info "Preregistering $hostname"
            New-ADComputer -Name $hostname -AccountPassword $joinPassword
            Write-Log -Level Info "Preregistered $hostname"
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
    (Get-Service w32time).WaitForStatus('Running', $(New-TimeSpan -seconds 15))
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
    if ((Get-Module -ListAvailable | where { $_.Name -eq 'ActiveDirectory' }) -eq $null) {
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
