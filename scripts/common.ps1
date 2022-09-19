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

#############################################################################
# Common PS that is included in other PS scripts,
# not to be executed on its own.
#############################################################################

#
# Common Functions
#

Function Install-Chocolately {
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

Function Install-LogDNAAgent {
    choco install -y logdna-agent
}

Function Write-LogDNAAgentConfig {
    logdna-agent -k ${ingestion_key}
    logdna-agent -d (Get-LogPath)
    logdna-agent -d ((Get-CDFPath) + "\*.csv")
    logdna-agent -d (Get-CCLogPath)
    logdna-agent -d (Get-CloudInitLogPath)
    logdna-agent -s LOGDNA_LOGHOST=logs.${region}.logging.cloud.ibm.com
    logdna-agent -t daas
}

Function Get-CCLogPath {
    return $env:LOCALAPPDATA + "\Temp\CitrixLogs\CloudServicesSetup"
}

Function Get-CloudInitLogPath {
    return $env:ProgramFiles + "\Cloudbase Solutions\Cloudbase-Init\log"
}

Function Get-CDFPath {
    return $env:SystemDrive + "\Logs\CDF"
}

Function Get-LogPath {
    return $env:ProgramData + "\IBMCitrixDaaS\logs"
}

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
    $LogFile = (Get-LogPath) + "\IBMCitrixDaaSInstallation.log"
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
    Write-Log -Level Info "Script Version: 2022.09.18"
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

Function Set-Dns {
    <#
    .SYNOPSIS
        Sets preferred DNS.

    .DESCRIPTION
        This function sets the preferred IP address for DNS.

    .PARAMETER $PrefferedDNSServer
        IP Address to set as preferred DNS address.
    #>
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
        $Interface = Get-WmiObject Win32_NetworkAdapterConfiguration
        $dnsServers = $Interface | Select-Object -ExpandProperty DNSServerSearchOrder
        Write-Log -Level Info "Modified DNS Search Order: $dnsServers"
    } else {
        Write-Log -Level Error "Incorrect Preferred Dns Server $PreferredDnsServer"
        exit 1
    }
}

#
# Common Exec
#

# Setup Log Path
If (!(Test-Path (Get-LogPath))) {New-Item -Path (Get-LogPath) -ItemType directory -Force}

# Install and Configure LogDNA if ingestion key present
If ( "${ingestion_key}" ) {
    # Install LogDNA
    try {
        Write-Log -Level Info "Installing LogDNA Agent"
        Install-Chocolately
        Install-LogDNAAgent
        Write-Log -Level Info "LogDNA Agent Installed"
    } catch {
        Write-Log -Level Error "LogDNA Agent Install Failed"
    }

    # Configure LogDNA
    try {
        Write-Log -Level Info "Configure LogDNA"
        Write-LogDNAAgentConfig
        nssm start logdna-agent
        Write-Log -Level Info "LogDNA Agent Configured"
    } catch {
        Write-Log -Level Error "LogDNA Agent Configuration Failed"
    }
}
