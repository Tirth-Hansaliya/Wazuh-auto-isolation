# Wazuh cross-platform malware detection + auto-isolation (2-minute release)

Requires Wazuh 4.2+ (JSON active-response protocol). Windows, Linux (systemd), macOS.

## 1. How it works

```
DETECT                          ALERT (manager)         ISOLATE (agent)              RELEASE (agent)
Windows : Defender real-time -> rule 100220 ─┐
Linux   : ClamAV recent/full -> rule 100230 ─┼─> active-response ─> isolate.cmd/.sh ─> watchdog service
macOS   : ClamAV recent/full -> rule 100230 ─┤   (no <timeout>)    writes state files    releases at +120 s
All OS  : FIM + VirusTotal   -> rule 100200 ─┘
```

**One release mechanism per OS** (this is what removes the conflicts):

| Old (conflicting)                          | New                                                    |
|--------------------------------------------|--------------------------------------------------------|
| Wazuh `<timeout>` + one-shot task + sleeper | Wazuh `<timeout>` removed, `timeout_allowed=no`        |
| Release time kept in several places         | `release_at` state file, read by one watchdog service  |
| Alert while isolated restarted the timer    | Ignored (`IGNORED`), timer is never extended           |
| Alert after release isolated again at once  | 300 s cooldown (`SUPPRESSED`), plus file quarantine    |
| Lost on reboot / agent restart              | Watchdog starts at boot and releases expired isolation |

State lives in `<agent>/var/isolation` (Windows: `ossec-agent\isolation`): `isolated_at`, `release_at`, `released_at`.

### Detection scope (what "system-wide" means here)
* **Windows:** Defender scans every file in real time, plus a weekly full scan (set by the installer).
* **Linux / macOS:** ClamAV scans every file changed on the system (by `ctime`, so faked timestamps do not hide files) every 5 minutes, and the full filesystem weekly. Detection latency is up to about 5 minutes, not instant. There is no fanotify/on-access scanner in this bundle.
* **FIM + VirusTotal** is an optional extra layer on high-risk folders only. Real-time FIM on `/` or `C:\` is not practical (inotify limits, I/O load, VirusTotal quota of 4 lookups/minute).
* Not covered: Solaris, AIX, HP-UX, BSD. The logic would need a port to their firewalls (`pf`, `ipf`, `ipfilter`).

## 2. Files and where they go

| File (this bundle)                  | Destination                                                                 |
|-------------------------------------|-----------------------------------------------------------------------------|
| `manager/ossec.conf.snippet.xml`    | Manager `/var/ossec/etc/ossec.conf` (inside `<ossec_config>`)               |
| `manager/local_rules.xml`           | Manager `/var/ossec/etc/rules/local_rules.xml` (append)                     |
| `manager/agent.conf`                | Manager `/var/ossec/etc/shared/default/agent.conf` (per-OS FIM, auto-pushed)|
| `linux-macos/*.sh`                  | Run `install-linux.sh` / `install-macos.sh`; copies to `<agent>/active-response/bin/` |
| `windows/*.ps1, *.cmd`              | Run `install-windows.ps1`; copies to `C:\Program Files (x86)\ossec-agent\active-response\bin\` |

Installers also: install ClamAV (Linux/macOS), add the `wazuh-av.log` localfile and the scan wodles to the agent's `ossec.conf`, create the watchdog (systemd service / LaunchDaemon / scheduled task) and restart the agent.

## 3. Deploy

### Manager
1. In `/var/ossec/etc/ossec.conf` **delete the old** `isolate-win` / `deisolate-win` commands and the old `<active-response>` block (with `<timeout>120</timeout>`). Paste `ossec.conf.snippet.xml` and set your VirusTotal key.
2. Append `local_rules.xml` to `/var/ossec/etc/rules/local_rules.xml` (keep your existing 100200 only once).
3. Replace/merge `/var/ossec/etc/shared/default/agent.conf` with `manager/agent.conf`.
4. Validate and restart:
```bash
/var/ossec/bin/wazuh-analysisd -t
systemctl restart wazuh-manager
cat /var/ossec/etc/shared/ar.conf | grep isolate     # expect isolate-endpoint-win0 / isolate-endpoint-unix0
```
Do **not** install these scripts on the manager itself (agent 000), or an alert would isolate the Wazuh server.

### Linux / Ubuntu (each endpoint)
```bash
sudo sh install-linux.sh
```
### macOS (each endpoint)
```bash
brew install clamav            # as normal user
sudo sh install-macos.sh
```
Then grant Full Disk Access (System Settings > Privacy & Security) to `/Library/Ossec/bin/wazuh-agent`, `/bin/sh`, `clamscan`.
### Windows (each endpoint, Admin PowerShell)
```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install-windows.ps1
```
Keep the Windows Firewall enabled; the script switches a disabled profile on during isolation and restores it afterwards.

Tunables: `$Duration`, `$Cooldown`, `$ExtraAllow` at the top of `isolate.ps1`; `ISO_DURATION`, `ISO_COOLDOWN`, `ISO_EXTRA_ALLOW` in `isolate.sh`. Isolation cuts SSH/RDP too, so add your admin host to `ExtraAllow` for production.

## 4. Test (use VMs, console access, never your only admin session)

Success log lines on every OS (`active-responses.log`):
`ISOLATED ... -> (IGNORED/SUPPRESSED on repeats) -> RELEASED ... after 120s (watchdog)`

**Safe dry run first (Linux/macOS, changes no firewall):**
```bash
sudo ISO_DRY_RUN=1 /var/ossec/active-response/bin/isolate.sh add
sudo /var/ossec/active-response/bin/isolate.sh status
sudo /var/ossec/active-response/bin/isolate.sh delete test
```

**1. Detection**
* Windows: `Set-Content C:\Users\Public\eicar.com 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'`
  (Defender blocks the write, that is expected). Check: `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=1116} -MaxEvents 1`
* Linux/macOS: `printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' | sudo tee /tmp/eicar.com >/dev/null`
  then speed it up: `sudo /var/ossec/active-response/bin/wazuh-av-scan.sh recent` (macOS: `/Library/Ossec/...`). Log: `tail /var/ossec/logs/wazuh-av.log` shows `DETECTED sig=Eicar-Signature`.
* Manager: `grep -E '"id":"(100220|100230)"' /var/ossec/logs/alerts/alerts.json | tail -2`
  Rule check without an agent: `/var/ossec/bin/wazuh-logtest`, paste `Oct 19 14:10:00 host wazuh-av: DETECTED sig=Eicar-Signature action=none path=/tmp/x` -> rule 100230.

**2. Isolation**: right after detection, the endpoint must lose everything except the manager.
* Linux/macOS: `curl -m 3 -sI https://1.1.1.1 >/dev/null && echo REACHABLE || echo BLOCKED`
* Windows: `Test-NetConnection 1.1.1.1 -Port 443 -InformationLevel Quiet`  (not ping, NAT gateways answer pings)
* Manager: `/var/ossec/bin/agent_control -l` must still show the agent `Active`.

**3 + 4. Automatic release after 2 minutes, with no manual step**: run the loop and do nothing.
```bash
for i in $(seq 1 16); do date +%T; curl -m 3 -sI https://1.1.1.1 >/dev/null && echo up || echo DOWN; sleep 10; done
```
```powershell
1..16 | % { Get-Date -f T; Test-NetConnection 1.1.1.1 -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue; Start-Sleep 10 }
```
Expect DOWN for about 120 s, then up.

**5. Logs**
```bash
grep -E 'isolate: (ISOLATED|RELEASED|IGNORED|SUPPRESSED|ABORT|ERROR)' /var/ossec/logs/active-responses.log
```
```powershell
Select-String 'isolate: ' "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" | select -Last 10
```
Dashboard / manager: filter `rule.id: (100220 or 100230 or 100210 or 100211 or 100212)`.
Compare the `ISOLATED` and `RELEASED` timestamps: 120-121 s apart.

**6. No loops**: while isolated, create 2-3 more EICAR files and rescan. Expected: `IGNORED ... timer not extended`, and `RELEASED` still at +120 s. Create one more within 5 minutes after release: `SUPPRESSED ... cooldown`. After the cooldown a new detection isolates again once. Quarantined files (`<agent>/quarantine`) do not re-alert; set `AV_QUARANTINE=no` in `wazuh-av-scan.sh` to disable quarantine.

**Crash tests**: restart the agent while isolated (release still happens), or reboot (the watchdog releases on boot).

## 4b. Firewall-off alert (rule 100240, alert only)
`firewall-check` runs on every endpoint every 10 minutes (Wazuh `localfile` command) and prints `fw-check: FIREWALL_OFF ...` only when the firewall is off. Windows: any profile disabled. Linux: no firewalld/ufw and no iptables/nftables rules. macOS: Application Firewall disabled. The manager rule 100240 (level 10) raises the alert; it does not isolate. To isolate on it too, add `100240` to `<rules_id>` in the manager `ossec.conf`.
Re-run the installers on existing endpoints (they are idempotent), then restart the manager after adding the rule.
Test: Windows `Set-NetFirewallProfile -Profile Public -Enabled False`; Linux `sudo ufw disable` or `sudo nft flush ruleset`; macOS `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off`. Within 10 minutes: `grep '"id":"100240"' /var/ossec/logs/alerts/alerts.json | tail -1`. Re-enable afterwards.
Alerts repeat every 10 minutes while the firewall stays off. Hosts that use a third-party firewall will alert on Windows; exclude them with a rule `<if_sid>100240</if_sid><agent_name>` or by tuning the script.

## 5. Troubleshooting
* No `ISOLATED` line: `grep isolate /var/ossec/etc/shared/ar.conf` on the agent, and `ossec.log` for "command not present". Check the file names and that the scripts are in `active-response/bin`.
* `ABORT manager IP not found`: `<address>` in the agent's `ossec.conf` is a placeholder or unresolvable. Set `MANAGER_IPS` / `$ManagerIP`.
* Windows: isolation has no effect if Windows Firewall is off (the script turns it on) or if a Group Policy ignores local rules (`Get-NetFirewallProfile -PolicyStore ActiveStore`).
* Linux without systemd: run `isolation-watchdog.sh` from your init system; without a watchdog, release only happens on the next alert (self-heal).
* ClamAV `clamscan` loads about 1 GB of signatures per run; on small hosts install `clamav-daemon` (the scan script uses `clamdscan` automatically).
* Limits: Windows version handles IPv4 managers only; manager hostnames must resolve at isolation time.
