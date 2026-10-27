# Wazuh Cross-Platform Malware Detection and Auto-Isolation

*Deployment and Test Guide with Configurable Isolation Duration*

**Requirements:** Wazuh 4.2 or later (JSON active-response protocol). **Supported platforms:** Windows, Linux (systemd), macOS.

## 1. Overview

This solution detects malware on endpoints, isolates the infected host from the network, and automatically restores connectivity after a configurable period. The isolation duration is no longer fixed at 120 seconds. It is a single setting (`T`) that you define per environment. The default remains 120 seconds.

### 1.1 Workflow

| Stage | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Detect | Defender real-time protection (rule 100220) | ClamAV recent/full scan (rule 100230) | ClamAV recent/full scan (rule 100230) |
| Alert (manager) | Active-response triggered, no Wazuh `<timeout>` | Same | Same |
| Isolate (agent) | `isolate.cmd` writes state files | `isolate.sh` writes state files | `isolate.sh` writes state files |
| Release (agent) | Watchdog scheduled task releases at isolation time + T | Watchdog systemd service | Watchdog LaunchDaemon |

On all operating systems, FIM + VirusTotal (rule 100200) is an optional additional detection layer.

### 1.2 Single release mechanism

Earlier versions used several overlapping release paths, which caused conflicts. The current design uses one mechanism per operating system.

| Previous behavior (conflicting) | Current behavior |
| --- | --- |
| Wazuh `<timeout>`, a one-shot task and a sleeper process | Wazuh `<timeout>` removed; `timeout_allowed=no` |
| Release time stored in several places | One `release_at` state file, read by a single watchdog service |
| An alert during isolation restarted the timer | Ignored (`IGNORED`); the timer is never extended |
| An alert right after release re-isolated immediately | Cooldown applies (`SUPPRESSED`), plus file quarantine |
| Isolation lost on reboot or agent restart | Watchdog starts at boot and releases expired isolation |

State files are stored in `<agent>/var/isolation` (Windows: `ossec-agent\isolation`) and are named `isolated_at`, `release_at` and `released_at`.

### 1.3 Detection scope

- **Windows:** Defender scans every file in real time, plus a weekly full scan configured by the installer.
- **Linux and macOS:** ClamAV scans every file changed on the system every 5 minutes, using ctime so that falsified timestamps do not hide files, and scans the full filesystem weekly. Detection latency is up to about 5 minutes. There is no fanotify or on-access scanner in this bundle.
- **FIM + VirusTotal:** An optional layer for high-risk folders only. Real-time FIM on `/` or `C:\` is impractical because of inotify limits, I/O load and the VirusTotal quota of 4 lookups per minute.
- **Not covered:** Solaris, AIX, HP-UX and BSD. The logic would need to be ported to their firewalls (pf, ipf, ipfilter).

## 2. Configuring the Isolation Duration

The release time is controlled by the following tunables. Values are in seconds. Choose a value that fits your response process (for example, 300 s for 5 minutes or 1800 s for 30 minutes).

| Platform | File | Setting | Default |
| --- | --- | --- | --- |
| Windows | `isolate.ps1` | `$Duration` | 120 |
| Linux / macOS | `isolate.sh` | `ISO_DURATION` | 120 |

Related settings:

| Setting | Windows | Linux / macOS | Purpose |
| --- | --- | --- | --- |
| Cooldown after release | `$Cooldown` | `ISO_COOLDOWN` | Prevents immediate re-isolation (default 300 s) |
| Extra allowed hosts | `$ExtraAllow` | `ISO_EXTRA_ALLOW` | Hosts reachable during isolation, such as an admin workstation |

**Recommendations**

- Set the cooldown (`Cooldown`) to a value equal to or greater than the isolation duration, so that a new isolation cannot begin before the host has had time to recover.
- Isolation also blocks SSH and RDP. Add your administration host to the extra-allow list for production use.
- After changing a value, redeploy the script (re-run the installer; it is idempotent) so the new duration takes effect on each endpoint.
- In this document, **T** refers to the duration you configured. Wherever the original guide referred to "120 s" or "2 minutes", use T.

## 3. Files and Destinations

| File (bundle) | Destination |
| --- | --- |
| `manager/ossec.conf.snippet.xml` | Manager `/var/ossec/etc/ossec.conf`, inside `<ossec_config>` |
| `manager/local_rules.xml` | Manager `/var/ossec/etc/rules/local_rules.xml` (append) |
| `manager/agent.conf` | Manager `/var/ossec/etc/shared/default/agent.conf` (per-OS FIM, pushed automatically) |
| `linux-macos/*.sh` | Installed by `install-linux.sh` / `install-macos.sh` into `<agent>/active-response/bin/` |
| `windows/*.ps1`, `*.cmd` | Installed by `install-windows.ps1` into `C:\Program Files (x86)\ossec-agent\active-response\bin\` |

The installers also install ClamAV (Linux/macOS), add the `wazuh-av.log` localfile and scan wodles to the agent `ossec.conf`, create the watchdog (systemd service, LaunchDaemon or scheduled task), and restart the agent.

## 4. Deployment

### 4.1 Manager

1. In `/var/ossec/etc/ossec.conf`, delete the old `isolate-win` and `deisolate-win` commands and the old `<active-response>` block (the one containing `<timeout>120</timeout>`).
2. Paste `ossec.conf.snippet.xml` and set your VirusTotal API key.
3. Append `local_rules.xml` to `/var/ossec/etc/rules/local_rules.xml`. Keep your existing rule 100200 only once.
4. Replace or merge `/var/ossec/etc/shared/default/agent.conf` with `manager/agent.conf`.
5. Validate and restart:

```bash
/var/ossec/bin/wazuh-analysisd -t
systemctl restart wazuh-manager
cat /var/ossec/etc/shared/ar.conf | grep isolate   # expect isolate-endpoint-win0 / isolate-endpoint-unix0
```

> **Warning:** Do not install these scripts on the manager itself (agent 000). Otherwise an alert would isolate the Wazuh server.

### 4.2 Linux / Ubuntu (each endpoint)

```bash
sudo sh install-linux.sh
```

### 4.3 macOS (each endpoint)

```bash
brew install clamav        # as a normal user
sudo sh install-macos.sh
```

Then grant Full Disk Access (System Settings > Privacy & Security) to `/Library/Ossec/bin/wazuh-agent`, `/bin/sh` and `clamscan`.

### 4.4 Windows (each endpoint, Administrator PowerShell)

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install-windows.ps1
```

Keep Windows Firewall enabled. If a profile is disabled, the script switches it on during isolation and restores it afterwards.

## 5. Testing

Use virtual machines with console access. Never test on your only administrative session.

**Expected log sequence on every OS** (`active-responses.log`): `ISOLATED` → (`IGNORED` / `SUPPRESSED` on repeats) → `RELEASED ... after Ts (watchdog)`.

### 5.1 Safe dry run (Linux/macOS, no firewall changes)

```bash
sudo ISO_DRY_RUN=1 /var/ossec/active-response/bin/isolate.sh add
sudo /var/ossec/active-response/bin/isolate.sh status
sudo /var/ossec/active-response/bin/isolate.sh delete test
```

### 5.2 Test 1: Detection

**Windows**

```powershell
Set-Content C:\Users\Public\eicar.com 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=1116} -MaxEvents 1
```

Defender blocks the write; this is expected.

**Linux / macOS**

```bash
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' | sudo tee /tmp/eicar.com >/dev/null
sudo /var/ossec/active-response/bin/wazuh-av-scan.sh recent    # macOS: /Library/Ossec/...
tail /var/ossec/logs/wazuh-av.log                              # expect DETECTED sig=Eicar-Signature
```

**Manager**

```bash
grep -E '"id":"(100220|100230)"' /var/ossec/logs/alerts/alerts.json | tail -2
```

To check the rule without an agent, run `/var/ossec/bin/wazuh-logtest` and paste: `Oct 19 14:10:00 host wazuh-av: DETECTED sig=Eicar-Signature action=none path=/tmp/x` (expected: rule 100230).

### 5.3 Test 2: Isolation

Right after detection, the endpoint must lose all connectivity except to the manager.

```bash
# Linux / macOS
curl -m 3 -sI https://1.1.1.1 >/dev/null && echo REACHABLE || echo BLOCKED
```

```powershell
# Windows (do not use ping; NAT gateways answer pings)
Test-NetConnection 1.1.1.1 -Port 443 -InformationLevel Quiet
```

On the manager, `/var/ossec/bin/agent_control -l` must still show the agent as Active.

### 5.4 Test 3: Automatic release after T seconds

Run the loop below and take no manual action. Set the loop length to cover T plus a margin. The example assumes the default T = 120 s (16 iterations × 10 s = 160 s). For a different T, change the iteration count to at least (T ÷ 10) + 4.

```bash
for i in $(seq 1 16); do date +%T; curl -m 3 -sI https://1.1.1.1 >/dev/null && echo up || echo DOWN; sleep 10; done
```

```powershell
1..16 | % { Get-Date -f T; Test-NetConnection 1.1.1.1 -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue; Start-Sleep 10 }
```

**Expected result:** `DOWN` for approximately T seconds, then `up`.

### 5.5 Test 4: No isolation loops

While the host is isolated, create two or three more EICAR files and rescan.

- **Expected:** `IGNORED ... timer not extended`, and `RELEASED` still occurs at +T.
- Create one more file within the cooldown period after release: `SUPPRESSED ... cooldown`.
- After the cooldown, a new detection isolates the host again, once.
- Quarantined files (`<agent>/quarantine`) do not re-alert. Set `AV_QUARANTINE=no` in `wazuh-av-scan.sh` to disable quarantine.

### 5.6 Crash tests

Restart the agent while the host is isolated (release must still happen), or reboot the host (the watchdog releases on boot).

## 6. Monitoring and Logs

```bash
grep -E 'isolate: (ISOLATED|RELEASED|IGNORED|SUPPRESSED|ABORT|ERROR)' /var/ossec/logs/active-responses.log
```

```powershell
Select-String 'isolate: ' "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" | select -Last 10
```

In the dashboard or on the manager, filter on `rule.id: (100220 or 100230 or 100210 or 100211 or 100212)`. The `ISOLATED` and `RELEASED` timestamps should differ by T seconds (about T to T+1 s).

## 7. Firewall-Off Alert (Rule 100240, Alert Only)

`firewall-check` runs on every endpoint every 10 minutes (Wazuh localfile command) and prints `fw-check: FIREWALL_OFF ...` only when the firewall is off.

| Platform | Condition treated as "firewall off" |
| --- | --- |
| Windows | Any profile disabled |
| Linux | No firewalld/ufw and no iptables/nftables rules |
| macOS | Application Firewall disabled |

Manager rule 100240 (level 10) raises the alert. It does **not** isolate. To isolate on this rule as well, add 100240 to `<rules_id>` in the manager `ossec.conf`. Re-run the installers on existing endpoints (they are idempotent) and restart the manager after adding the rule.

**Test commands**

- Windows: `Set-NetFirewallProfile -Profile Public -Enabled False`
- Linux: `sudo ufw disable` or `sudo nft flush ruleset`
- macOS: `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off`

Within 10 minutes, verify on the manager:

```bash
grep '"id":"100240"' /var/ossec/logs/alerts/alerts.json | tail -1
```

Re-enable the firewall afterwards. Alerts repeat every 10 minutes while the firewall remains off. Hosts that use a third-party firewall will alert on Windows; exclude them with a rule such as `<if_sid>100240</if_sid><agent_name>`, or by tuning the script.

## 8. Troubleshooting

| Symptom | Likely cause and action |
| --- | --- |
| No `ISOLATED` line | Run `grep isolate /var/ossec/etc/shared/ar.conf` on the agent and check `ossec.log` for "command not present". Verify file names and that scripts are in `active-response/bin`. |
| `ABORT manager IP not found` | `<address>` in the agent `ossec.conf` is a placeholder or unresolvable. Set `MANAGER_IPS` (Linux/macOS) or `$ManagerIP` (Windows). |
| Windows isolation has no effect | Windows Firewall is off (the script turns it on), or a Group Policy ignores local rules. Check with `Get-NetFirewallProfile -PolicyStore ActiveStore`. |
| Linux without systemd | Run `isolation-watchdog.sh` from your init system. Without a watchdog, release only happens on the next alert (self-heal). |
| High memory use during scans | `clamscan` loads about 1 GB of signatures per run. On small hosts install `clamav-daemon`; the scan script then uses `clamdscan` automatically. |
| Host not released at T | Confirm the configured duration in `isolate.sh` / `isolate.ps1`, that the watchdog is running, and review the `release_at` state file. |

**Known limits:** The Windows version supports IPv4 managers only. Manager hostnames must resolve at isolation time.

## 9. Summary of Changes in This Version

- The fixed 2-minute release is replaced by a configurable duration (`$Duration` / `ISO_DURATION`, default 120 s).
- All test timings and log expectations are expressed in terms of T.
- Added guidance on aligning cooldown with the chosen duration.
