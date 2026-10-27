# isolation-watchdog.ps1 - the ONLY thing that releases an isolated Windows endpoint.
# Runs as the scheduled task "WazuhIsolationWatchdog" (SYSTEM, at startup, auto-restart).
# Checks once a second -> release happens 120-121 s after isolation, and also
# right after a reboot, because Windows Firewall rules survive reboots.
$AgentDir = "C:\Program Files (x86)\ossec-agent"
$StateDir = Join-Path $AgentDir "isolation"
$Iso      = Join-Path $AgentDir "active-response\bin\isolate.ps1"
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null

& $Iso -Action cleanup                 # remove orphaned rules left by a crash/reboot
while ($true) {
    try {
        $f = "$StateDir\release_at"
        if (Test-Path $f) {
            $r = 0L
            $txt = (Get-Content $f -ErrorAction Stop | Select-Object -First 1)
            if ([long]::TryParse($txt, [ref]$r) -and $r -gt 0 -and [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -ge $r) {
                & $Iso -Action delete -Reason watchdog
            }
        }
    } catch {}
    Start-Sleep -Seconds 1
}
