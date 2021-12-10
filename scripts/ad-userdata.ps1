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
Function Create-Task {
    Write-Log -Level Info "Creating adsetup.ps1"
    Copy-Item "$($MyInvocation.ScriptName)" -Destination "C:\adsetup.ps1"
    Write-Log -Level Info "Creating task to run adsetup.ps1 after reboot"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\adsetup.ps1"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $trigger.delay = "PT10M"
    $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName "ADFinalSetup" -TaskPath "\" -Action $action -Trigger $trigger -Principal $principal
}
Function Run-Install {
    if (Check-Install -eq $true) {
        Write-Log -Level Info "ActiveDirectory is installed"
        (Get-Service ADWS).WaitForStatus('Running', $(New-TimeSpan -seconds 30))
        $configuration = @{
            connectorHosts = [System.Collections.ArrayList]@()
        }
        for ($i = 1; $i -le ${connector_depth}; $i++) {
            $configuration['connectorHosts'].Add("${connector_name}-${resource_identifier}-$i")
        }
        Write-Log -Level Info "ADWS: $((Get-Service ADWS).Status) Hostnames: $($configuration['connectorHosts'])"
        $joinPassword = (ConvertTo-SecureString -String "${ad_join_pwd}" -AsPlainText -Force)
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
    Create-Task
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
        Write-Log -Level Info "Adding ADDSForest"

        $result = Install-ADDSForest -CreateDnsDelegation:$false `
            -SafeModeAdministratorPassword (ConvertTo-SecureString -String "${ad_safe_pwd}" -AsPlainText -Force) `
            -DatabasePath "C:\Windows\NTDS" `
            -DomainMode "WinThreshold" `
            -DomainName ${ad_domain_name} `
            -DomainNetbiosName ${netbios_name} `
            -ForestMode "WinThreshold" `
            -InstallDns:$true `
            -LogPath "C:\Windows\NTDS" `
            -NoRebootOnCompletion:$true `
            -SysvolPath "C:\Windows\SYSVOL" `
            -Force:$true
        Write-Log -Level Info "ActiveDirectory: $($result.Message)"
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
if ("${topology}" -eq "Extended") {
    Write-Log -Level Info "Manual AD setup required for Extended topology."
    exit 0
}
$activeDirectoryInstalled = Run-Install
Write-Log -Level Info "Active Directory setup complete ($activeDirectoryInstalled) "
if ($activeDirectoryInstalled) {
        Write-Log -Level Info "Active Directory Installed - restart and do not run this script on next boot (1001)"
exit 1001
}
exit 0
