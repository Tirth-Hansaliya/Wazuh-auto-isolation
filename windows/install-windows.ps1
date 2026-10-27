# install-windows.ps1 - run in an ADMIN PowerShell on every Windows endpoint
#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$Src      = $PSScriptRoot
$AgentDir = "C:\Program Files (x86)\ossec-agent"
$Bin      = Join-Path $AgentDir "active-response\bin"
if (-not (Test-Path $Bin)) { throw "Wazuh agent not found at $AgentDir (edit `$AgentDir here and in the .ps1 files)" }

Write-Host "[1/5] Removing the old one-shot failsafe task and old test leftovers"
Unregister-ScheduledTask -TaskName "WazuhDeisolate" -Confirm:$false -ErrorAction SilentlyContinue
Get-NetFirewallRule -DisplayName "WAZUH-ISOLATE*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
try { Remove-MpPreference -ExclusionPath "C:\Temp" -ErrorAction Stop } catch {}

Write-Host "[2/5] Copying scripts to $Bin"
foreach ($f in "isolate.cmd","deisolate.cmd","isolate.ps1","deisolate.ps1","isolation-watchdog.ps1","firewall-check.ps1") {
    Copy-Item (Join-Path $Src $f) $Bin -Force
}

Write-Host "[3/5] Watchdog scheduled task (single release mechanism)"
$act  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Bin\isolation-watchdog.ps1`""
$trg  = New-ScheduledTaskTrigger -AtStartup
$prin = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$set  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName "WazuhIsolationWatchdog" -Action $act -Trigger $trg -Principal $prin -Settings $set -Force | Out-Null
Stop-ScheduledTask -TaskName "WazuhIsolationWatchdog" -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName "WazuhIsolationWatchdog"

Write-Host "[4/5] Microsoft Defender: real-time protection on, weekly full scan"
try {
    Set-MpPreference -DisableRealtimeMonitoring $false -DisableIOAVProtection $false -DisableBehaviorMonitoring $false `
        -ScanParameters FullScan -ScanScheduleDay Sunday -ScanScheduleTime (New-TimeSpan -Hours 2)
    Update-MpSignature -ErrorAction SilentlyContinue
} catch { Write-Warning "Could not configure Defender (another AV active or blocked by policy?): $($_.Exception.Message)" }

Write-Host "[5/5] Agent config + restart"
$conf = Join-Path $AgentDir "ossec.conf"
if (-not (Select-String -Path $conf -Pattern "Windows Defender/Operational" -Quiet)) {
    Add-Content -Path $conf -Encoding ASCII -Value @"
<ossec_config>
  <localfile>
    <location>Microsoft-Windows-Windows Defender/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
"@
    Write-Host "  Defender event channel added to ossec.conf"
} else { Write-Host "  Defender event channel already collected, left unchanged" }
if (-not (Select-String -Path $conf -Pattern "WAZUH-FWCHECK" -Quiet)) {
    Add-Content -Path $conf -Encoding ASCII -Value @"
<!-- WAZUH-FWCHECK BEGIN -->
<ossec_config>
  <localfile>
    <log_format>command</log_format>
    <alias>fw-check</alias>
    <command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files (x86)\ossec-agent\active-response\bin\firewall-check.ps1"</command>
    <frequency>600</frequency>
  </localfile>
</ossec_config>
<!-- WAZUH-FWCHECK END -->
"@
    Write-Host "  firewall-check added to ossec.conf"
}
Restart-Service WazuhSvc
Write-Host "Done. Check: Get-ScheduledTask WazuhIsolationWatchdog | Get-ScheduledTaskInfo"
