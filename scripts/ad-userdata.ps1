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
    Installs root Active Directory domain controller.

.DESCRIPTION
    This script installs and configures a root Active Directory domain controller with pre-registered
    Cloud Connectors.

.NOTES
    This script is used by the IBM Cloud topology and executed post server deployment by Cloudbase-Init.
#>

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
    Write-Log -Level Info "The OS Version is $env:OSVersion.Version"
    Write-Log -Level Info "Host Version $($Host.Version)"
    $DotNet = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
    Write-Log -Level Info ".NET version/release $($DotNet.version)/$($DotNet.release)"
}

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
    Register-ScheduledTask -TaskName "ADFinalSetup" -TaskPath "\" -Action $action -Trigger $trigger -Principal $principal
}

Function Create-Site {
    <#
    .SYNOPSIS
        Creates Active Directory Site.

    .DESCRIPTION
        This function creates an Active Directory Replication Site with specified site name.

    .PARAMETER $SiteName
        Site name to use for Active Directory.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $SiteName
    )

    try {
        $siteAD = New-ADReplicationSite -Name $SiteName  -ErrorAction Stop -PassThru
    } catch {
        Write-Log -Level Info ("ADReplicationSite " + $SiteName + " could not be created. Reason: " + $_.Exception.Message)
        return $null
    }
    
    try {
        $siteAD = Set-ADReplicationSite -Identity $siteAD  -ErrorAction Stop -PassThru
    } catch {
        Write-Log -Level Info ("ADReplicationSite " + $siteAD.Name + " could not be set. Reason: " + $_.Exception.Message) 
    }

	return $siteAD
}

Function Create-Subnet {
    <#
    .SYNOPSIS
        Creates Active Directory Subnet.

    .DESCRIPTION
        This function creates an Active Directory Replication Subnet with specified subnet and Active
        Directory Site.

    .PARAMETER $Subnet
        Subnet to use for Active Directory Site.

    .PARAMETER $SiteAD
        Site to use for Active Directory Subnet.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Subnet,

        [Parameter(Mandatory = $true)]
        [string]
        $SiteAD
    )

	try {
		$subnetAD = New-ADReplicationSubnet -Name $subnet -Site $SiteAD -ErrorAction Stop -PassThru
	} catch {
		Write-Log -Level Info ("ADReplicationSubnet " + $subnet + " could not be created. Reason: " + $_.Exception.Message) 
		return $null
	}
	return $subnetAD
}

Function Custom-InstallADForest {
    <#
    .SYNOPSIS
        Installs Active Directory Domain Controller.

    .DESCRIPTION
        This function installs the Active Directory Domain Controller given credential and domain
        information input.
    #>
    $result = Install-ADDSForest -CreateDnsDelegation:$false `
                -SafeModeAdministratorPassword (ConvertTo-SecureString -String "${ad_safe_pwd}" -AsPlainText -Force) `
                -DatabasePath "C:\Windows\NTDS" `
                -DomainMode "WinThreshold" `
                -DomainName ${ad_domain_name} `
                -ForestMode "WinThreshold" `
                -InstallDns:$true `
                -LogPath "C:\Windows\NTDS" `
                -NoRebootOnCompletion:$true `
                -SysvolPath "C:\Windows\SYSVOL" `
                -Force:$true
    return $result
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

        $configuration = @{
            connectorHosts = [System.Collections.ArrayList]@()
        }

        $zones = "${zones}"
        $AdZones = $zones.Split(",")
        Write-Log -Level Info "Zones are ${zones}, current zone is ${zone_index}"
        $connectorCount = ${connector_reg_num} * $AdZones.count

        for ($i = 1; $i -le $connectorCount; $i++) {
            $configuration["connectorHosts"].Add("${connector_name}-${resource_identifier}-$i")
        }

        Write-Log -Level Info "ADWS: $((Get-Service ADWS).Status) Hostnames: $($configuration["connectorHosts"])"
        $joinPassword = (ConvertTo-SecureString -String "${ad_join_pwd}" -AsPlainText -Force)

        foreach ($hostname in $configuration["connectorHosts"]) {
            Write-Log -Level Info "Preregistering $hostname"
            New-ADComputer -Name $hostname -AccountPassword $joinPassword
            Write-Log -Level Info "Preregistered $hostname"
        }

        Write-Log -Level Info "Enabling SMB2 protocol."
        Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force

        if ($AdZones.count -gt 1) {
            $subnets = "${subnets}"
            $AdSubnets = $subnets.Split(",")

            # Root Active Directory Setup
            for ($i = 0; $i -lt $AdZones.count; $i++) {
                Write-Log -Level Info "Adding site $AdZones[$i]"
                $site = Create-Site -SiteName $AdZones[$i] 
                Write-Log -Level Info "Adding subnet $AdZones[$i]"
                Create-Subnet -Subnet $AdSubnets[$i] -SiteAD $site

                if ($i -eq 0) {
                    $siteDC = Get-ADDomainController -Discover -Site "Default-First-Site-Name"
                    Write-Log -Level Info "Move DC from default site to new site"
                    Move-ADDirectoryServer -Identity $siteDC -Site $AdZones[0]  
                } else {
                    Write-Log -Level Info "Adding link $AdZones[0], $AdZones[$i]"
                    New-ADReplicationSiteLink -Name "Link-$i" -SitesIncluded $AdZones[0],$AdZones[$i] -Cost 100 -ReplicationFrequencyInMinutes 15 -InterSiteTransportProtocol IP
                }
            }

            Remove-ADReplicationSite -Identity "Default-First-Site-Name" -Confirm:$false

            # Create Domain user with `Domain Admins` group for secondary active directories(Domain Controller)
            $Attributes = @{
                Enabled = $true
                ChangePasswordAtLogon = $false
                UserPrincipalName = "aduser@${ad_domain_name}"
                Name = "aduser"
                GivenName = "aduser"
                AccountPassword = "${ad_join_pwd}" | ConvertTo-SecureString -AsPlainText -Force
            }

            Write-Log -Level Info "Creating domain user"
            New-ADUser @Attributes
            Add-ADGroupMember -Identity "Domain Admins" -Members "aduser"
            Write-Log -Level Info "Adding alternate DNS"

            Retry-Command -ScriptBlock {
                # Check if other domain controllers have joined and update alternate DNS
                $IPs = (Get-ADForest).Domains | % { Get-ADDomainController -Filter * -Server $_} | Select-Object IPv4Address
                Write-Log -Level Info "IPs found $IPs"

                if ($IPs.count -gt 1) {
                    $Interface = Get-DnsClientServerAddress | Select-Object InterfaceIndex
                    Set-DnsClientServerAddress -InterfaceIndex $Interface[0].InterfaceIndex -ServerAddresses ("127.0.0.1", $IPs[1].IPv4Address)
                } else {
                    throw "Wait for other DC to join, IPs: $IPs"
                }
            } -Attempts 10
        }

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
        Write-Log -Level Info "Adding ADDSForest"
        $result = Custom-InstallADForest
        Write-Log -Level Info "ActiveDirectory: $($result.Message)"
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
$activeDirectoryInstalled = Run-Install
Write-Log -Level Info "Active Directory setup complete ($activeDirectoryInstalled) "

if ($activeDirectoryInstalled) {
        Write-Log -Level Info "Active Directory Installed - restart and do not run this script on next boot (1001)"
exit 1001
}
exit 0
