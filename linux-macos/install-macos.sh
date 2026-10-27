#!/bin/sh
# install-macos.sh - run with sudo on every macOS endpoint.
# Prerequisite (as your normal user, NOT root):  brew install clamav
set -e
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo: sudo sh install-macos.sh"; exit 1; }
SRC=$(cd "$(dirname "$0")" && pwd)
W=/Library/Ossec; BIN=$W/active-response/bin
[ -d "$BIN" ] || { echo "Wazuh agent not found in $W"; exit 1; }
PATH=/opt/homebrew/bin:/usr/local/bin:$PATH
command -v clamscan >/dev/null 2>&1 || { echo "ClamAV missing. As a normal user run: brew install clamav"; exit 1; }

echo "[1/5] ClamAV signatures"
P=$(dirname "$(dirname "$(command -v clamscan)")")
mkdir -p "$P/var/lib/clamav"
if [ ! -f "$P/etc/clamav/freshclam.conf" ] && [ -f "$P/etc/clamav/freshclam.conf.sample" ]; then
  cp "$P/etc/clamav/freshclam.conf.sample" "$P/etc/clamav/freshclam.conf"
  sed -i '' 's/^Example/#Example/' "$P/etc/clamav/freshclam.conf"
fi
freshclam || echo "WARNING: freshclam failed, check network / config"

echo "[2/5] Scripts -> $BIN"
for f in isolate.sh deisolate.sh isolation-watchdog.sh wazuh-av-scan.sh firewall-check.sh; do
  install -m 0750 -o root -g wheel "$SRC/$f" "$BIN/$f"
done
touch $W/logs/wazuh-av.log; chmod 640 $W/logs/wazuh-av.log

echo "[3/5] Agent config"
if ! grep -q 'WAZUH-ISOLATION BEGIN' $W/etc/ossec.conf; then
cat >> $W/etc/ossec.conf <<'EOF'
<!-- WAZUH-ISOLATION BEGIN -->
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/Library/Ossec/logs/wazuh-av.log</location>
  </localfile>
  <wodle name="command">
    <disabled>no</disabled>
    <tag>av-recent</tag>
    <command>/Library/Ossec/active-response/bin/wazuh-av-scan.sh recent</command>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>
    <ignore_output>yes</ignore_output>
    <timeout>900</timeout>
  </wodle>
  <wodle name="command">
    <disabled>no</disabled>
    <tag>av-full</tag>
    <command>/Library/Ossec/active-response/bin/wazuh-av-scan.sh full</command>
    <interval>7d</interval>
    <run_on_start>no</run_on_start>
    <ignore_output>yes</ignore_output>
    <timeout>0</timeout>
  </wodle>
  <wodle name="command">
    <disabled>no</disabled>
    <tag>av-update</tag>
    <command>/Library/Ossec/active-response/bin/wazuh-av-scan.sh update</command>
    <interval>1d</interval>
    <run_on_start>no</run_on_start>
    <ignore_output>yes</ignore_output>
    <timeout>600</timeout>
  </wodle>
</ossec_config>
<!-- WAZUH-ISOLATION END -->
EOF
fi

echo "[4/5] Watchdog LaunchDaemon"
PL=/Library/LaunchDaemons/com.wazuh.isolation-watchdog.plist
cat > $PL <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.wazuh.isolation-watchdog</string>
  <key>ProgramArguments</key><array><string>/Library/Ossec/active-response/bin/isolation-watchdog.sh</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
EOF
chown root:wheel $PL; chmod 644 $PL
launchctl bootout system $PL 2>/dev/null || true
launchctl bootstrap system $PL

if ! grep -q 'WAZUH-FWCHECK BEGIN' /Library/Ossec/etc/ossec.conf; then
cat >> /Library/Ossec/etc/ossec.conf <<'EOF'
<!-- WAZUH-FWCHECK BEGIN -->
<ossec_config>
  <localfile>
    <log_format>command</log_format>
    <alias>fw-check</alias>
    <command>/Library/Ossec/active-response/bin/firewall-check.sh</command>
    <frequency>600</frequency>
  </localfile>
</ossec_config>
<!-- WAZUH-FWCHECK END -->
EOF
fi

echo "[5/5] Restart agent"
$W/bin/wazuh-control restart
echo "Done. Also grant Full Disk Access (System Settings > Privacy & Security) to /Library/Ossec/bin/wazuh-agent, /bin/sh and clamscan, otherwise protected folders are skipped."
