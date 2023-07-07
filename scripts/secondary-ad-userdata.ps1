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
    This script installs and configures an extended Active Directory domain controller, joined to the
    root Active Directory domain with pre-registered Cloud Connectors. An Active Directory Site is created
    for this domain controller using the zone name.

.NOTES
    This script is used by the IBM Cloud topology and executed post server deployment by Cloudbase-Init.
#>

#
# Include Common PS
#
${common_ps}

Function Create-Task {
    <#
    .SYNOPSIS
        Creates task for reboot.

    .DESCRIPTION
        This function copies this script to the C drive and schedules a task to rerun the script 10
        minutes after reboot to complete setup.
    #>
    Write-Log -Level Info "Creating adsetup.ps1"
    Copy-Item "$($MyInvocation.ScriptName)" -Destination "C:\adsetup.ps1"
    Write-Log -Level Info "Creating task to run adsetup.ps1 after reboot"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\adsetup.ps1"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $trigger.delay = "PT10M"
    $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    try {
        Register-ScheduledTask -TaskName "ADFinalSetup" -TaskPath "\" -Action $action -Trigger $trigger -Principal $principal
    } catch {
        Write-Log -Level Error ("ScheduledTask ADFinalSetup could not be registered. Reason: " + $_.Exception.Message)
    }
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

    $Username = "${ad_domain_name}\aduser"
    $Password = "${ad_join_pwd}"
    $Password = ConvertTo-SecureString -String $Password -AsPlainText -Force
    $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username,$Password

    $result = Install-ADDSDomainController `
                -SafeModeAdministratorPassword (ConvertTo-SecureString -String "${ad_safe_pwd}" -AsPlainText -Force) `
                -NoGlobalCatalog:$false `
                -CreateDnsDelegation:$false `
                -DomainName ${ad_domain_name} `
                -Credential $Credentials `
                -CriticalReplicationOnly:$false `
                -DatabasePath "C:\Windows\NTDS" `
                -InstallDns:$true `
                -LogPath "C:\Windows\NTDS" `
                -NoRebootOnCompletion:$false `
                -ReplicationSourceDC "${root_ad_name}.${ad_domain_name}" `
                -SiteName $SiteName `
                -SysvolPath "C:\Windows\SYSVOL" `
                -Force:$true

    if ($?) {
        return $result
    }

    throw $result.Message
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
        Write-Log -Level Info "Setting alternate DNS for root AD to ${root_ad_ip}"
        $Interface = Get-DnsClientServerAddress | Select-Object InterfaceIndex, ServerAddresses
        Set-DnsClientServerAddress -InterfaceIndex $Interface[0].InterfaceIndex -ServerAddresses "127.0.0.1","${root_ad_ip}"
        Write-Log -Level Info "Enabling SMB2 protocol."
        Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
        Write-Log -Level Info "Run-Install Complete. Service: $(Get-ADDomainController -Discover -Service ADWS)"
        exit 0
    }

    Create-Task
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
        $zones = "${zones}"
        $AdZones = $zones.Split(",")
        Write-Log -Level Info "Setting DNS to primary active directory ${root_ad_ip}"
        Set-Dns "${root_ad_ip}"
        Import-Module ADDSDeployment
        Write-Log -Level Info "Site Name is $AdZones[${zone_index}], Root AD Name is ${root_ad_name}"

        Retry-Command -ScriptBlock {
            $result = Custom-InstallADDomainController -SiteName $AdZones[${zone_index}]
            Write-Log -Level Info "ActiveDirectory domain controller: $($result.Message)"
        } -Attempts 25

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
Write-Log -Level Info "Active Directory topology is ${topology}"
Write-Log -Level Info "Starting Secondary Active Directory setup"
$activeDirectoryInstalled = Run-Install
Write-Log -Level Info "Active Directory setup complete ($activeDirectoryInstalled) "

if ($activeDirectoryInstalled) {
        Write-Log -Level Info "Active Directory Installed - restart and do not run this script on next boot (1001)"
exit 1001
}
exit 0
