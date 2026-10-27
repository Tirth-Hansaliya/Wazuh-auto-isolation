# =============================================================================
# isolate.ps1 - Wazuh Active Response: network isolation for Windows
#   Wazuh calls it with JSON on stdin. Manual use:
#   .\isolate.ps1 -Action add | delete | cleanup | status
# Release is done ONLY by isolation-watchdog.ps1 (scheduled task at startup),
# never by Wazuh's <timeout> or a one-shot task.
# =============================================================================
param([string]$Action = "", [string]$Reason = "wazuh")

# ------------------------------- Tunables ------------------------------------
$Duration   = 120          # seconds isolated
$Cooldown   = 300          # seconds after release in which new alerts are ignored
$ExtraAllow = @()          # IPv4s that stay reachable, e.g. @("192.168.0.50")
$ManagerIP  = @()          # empty = auto-detect from the agent's ossec.conf
# -----------------------------------------------------------------------------

$AgentDir = "C:\Program Files (x86)\ossec-agent"
$StateDir = Join-Path $AgentDir "isolation"
$LogFile  = Join-Path $AgentDir "active-response\active-responses.log"
$RulePfx  = "WAZUH-ISOLATE"
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null

function Log($m) {
    $ts   = [DateTime]::Now.ToString('yyyy/MM/dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
    $line = "$ts active-response/bin/isolate: $m`r`n"
    try {   # open with ReadWrite share: the Wazuh agent keeps this file open
        $fs = [System.IO.File]::Open($LogFile, 'Append', 'Write', 'ReadWrite')
        $b  = [Text.Encoding]::ASCII.GetBytes($line); $fs.Write($b, 0, $b.Length); $fs.Close()
    } catch { try { Add-Content "C:\Windows\Temp\wazuh-isolate.log" $line } catch {} }
}
function Now { [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
function Read-Num($f) { try { [long](Get-Content $f -ErrorAction Stop | Select-Object -First 1) } catch { $null } }
function Write-Num($f, $v) { Set-Content -Path "$f.tmp" -Value $v -Encoding ASCII; Move-Item "$f.tmp" $f -Force }

# ---- Which IPv4 addresses must stay reachable --------------------------------
function Get-Targets {
    $list = @()
    if ($ManagerIP.Count) { $list += $ManagerIP }
    else {
        $c = Get-Content "$AgentDir\ossec.conf" -Raw
        $c = [regex]::Replace($c, '<!--.*?-->', '', 'Singleline')
        $list += [regex]::Matches($c, '<address>\s*([^<\s]+)\s*</address>') | ForEach-Object { $_.Groups[1].Value }
    }
    $list += $ExtraAllow
    $ips = foreach ($h in $list) {
        $ip = $null
        if ([System.Net.IPAddress]::TryParse($h, [ref]$ip)) {
            if ($ip.AddressFamily -eq 'InterNetwork') { $ip.ToString() }
        } else {
            try { [System.Net.Dns]::GetHostAddresses($h) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.ToString() } } catch {}
        }
    }
    @($ips | Sort-Object -Unique)
}

# ---- "everything except these IPs" as address ranges --------------------------
function ToUInt($ip) { $b = ([ipaddress]$ip).GetAddressBytes(); [array]::Reverse($b); [uint64][BitConverter]::ToUInt32($b, 0) }
function ToIP([uint64]$n) { $b = [BitConverter]::GetBytes([uint32]$n); [array]::Reverse($b); ([ipaddress]$b).ToString() }
function Get-BlockRanges($ips) {
    $nums = @($ips | ForEach-Object { ToUInt $_ } | Sort-Object -Unique)
    $ranges = @(); $start = [uint64]0
    foreach ($n in $nums) {
        if ($n -gt $start) { $ranges += "$(ToIP $start)-$(ToIP ($n - 1))" }
        $start = $n + 1
    }
    if ($start -le 4294967295) { $ranges += "$(ToIP $start)-255.255.255.255" }
    $ranges
}

# ---- Firewall --------------------------------------------------------------------
function Apply-Isolation($ips) {
    Get-NetFirewallRule -DisplayName "$RulePfx*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    # block rules are ignored while a profile is OFF: switch it on and remember
    $off = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
    if ($off.Count) {
        Set-Content "$StateDir\fw_was_off.txt" ($off -join ",") -Encoding ASCII
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
    }
    $r = Get-BlockRanges $ips
    $v6 = "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
    # a Block rule always beats any Allow rule, so block everything EXCEPT the manager
    New-NetFirewallRule -DisplayName "$RulePfx-BLOCK-OUT"  -Direction Outbound -Action Block -RemoteAddress $r  -Profile Any -ErrorAction Stop | Out-Null
    New-NetFirewallRule -DisplayName "$RulePfx-BLOCK-IN"   -Direction Inbound  -Action Block -RemoteAddress $r  -Profile Any -ErrorAction Stop | Out-Null
    New-NetFirewallRule -DisplayName "$RulePfx-BLOCK-OUT6" -Direction Outbound -Action Block -RemoteAddress $v6 -Profile Any -ErrorAction Stop | Out-Null
    New-NetFirewallRule -DisplayName "$RulePfx-BLOCK-IN6"  -Direction Inbound  -Action Block -RemoteAddress $v6 -Profile Any -ErrorAction Stop | Out-Null
}
function Remove-Isolation {
    Get-NetFirewallRule -DisplayName "$RulePfx*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $f = "$StateDir\fw_was_off.txt"
    if (Test-Path $f) {
        $p = (Get-Content $f) -split ","
        Set-NetFirewallProfile -Profile $p -Enabled False
        Remove-Item $f -Force
    }
}

# ---- State machine ------------------------------------------------------------------
function Release-Now($why) {            # caller holds the mutex
    $rel = Read-Num "$StateDir\release_at"
    Remove-Isolation
    if ($rel) {
        $t = Now; $st = Read-Num "$StateDir\isolated_at"; if (-not $st) { $st = $t }
        Remove-Item "$StateDir\isolated_at","$StateDir\release_at" -Force -ErrorAction SilentlyContinue
        Write-Num "$StateDir\released_at" $t
        Log "RELEASED endpoint, network restored after $($t - $st)s ($why)"
    }
}
function Do-Add {
    $t = Now
    $rel = Read-Num "$StateDir\release_at"
    if ($rel) {
        if ($t -lt $rel) { Log "IGNORED alert rule=$Rule : already isolated, release in $($rel - $t)s (timer not extended)"; return }
        Release-Now "expired, self-heal"           # watchdog was not running
    }
    $last = Read-Num "$StateDir\released_at"
    if ($last -and ($t - $last) -lt $Cooldown) {
        Log "SUPPRESSED alert rule=$Rule : cooldown, $($Cooldown - ($t - $last))s left (prevents isolation loops)"; return
    }
    $ips = Get-Targets
    if (-not $ips.Count) { Log "ABORT endpoint NOT isolated: manager IPv4 not found"; return }
    try {
        Apply-Isolation $ips
        Write-Num "$StateDir\isolated_at" $t
        Write-Num "$StateDir\release_at" ($t + $Duration)
        Remove-Item "$StateDir\released_at" -Force -ErrorAction SilentlyContinue
        Log "ISOLATED endpoint for ${Duration}s rule=$Rule allowed=$($ips -join ',')"
    } catch {
        Remove-Isolation
        Log "ERROR isolation failed, endpoint NOT isolated: $($_.Exception.Message)"
    }
}

# ---- Entry point -----------------------------------------------------------------------
$Rule = "manual"
if (-not $Action) {
    try {
        $raw = [Console]::In.ReadLine(); $j = $raw | ConvertFrom-Json
        $Action = $j.command
        if ($j.parameters.alert.rule.id) { $Rule = $j.parameters.alert.rule.id }
    } catch {}
}
if (-not $Action) { $Action = "add" }

$mutex = New-Object System.Threading.Mutex($false, "Global\WazuhIsolation")
$got = $false
try { $got = $mutex.WaitOne(30000) } catch [System.Threading.AbandonedMutexException] { $got = $true }
if (-not $got) { Log "ERROR could not get lock"; exit 1 }
try {
    switch ($Action) {
        "add"     { Do-Add }
        "delete"  { Release-Now $Reason }
        "cleanup" { if (-not (Test-Path "$StateDir\release_at")) { Remove-Isolation } }
        "status"  { $r = Read-Num "$StateDir\release_at"; if ($r) { "ISOLATED, release in $($r - (Now))s" } else { "not isolated" } }
    }
} finally { $mutex.ReleaseMutex() }
