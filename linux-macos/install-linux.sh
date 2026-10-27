#!/bin/sh
# install-linux.sh - run as root on every Linux / Ubuntu / Debian / RHEL / SUSE endpoint
set -e
[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo sh install-linux.sh"; exit 1; }
SRC=$(cd "$(dirname "$0")" && pwd)
W=/var/ossec; BIN=$W/active-response/bin
[ -d "$BIN" ] || { echo "Wazuh agent not found in $W"; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "systemd is required for the watchdog service"; exit 1; }
command -v nft >/dev/null 2>&1 || command -v iptables >/dev/null 2>&1 || echo "WARNING: install nftables or iptables, isolation needs one of them"

echo "[1/5] ClamAV"
if ! command -v clamscan >/dev/null 2>&1; then
  if   command -v apt-get >/dev/null 2>&1; then export DEBIAN_FRONTEND=noninteractive; apt-get update -y && apt-get install -y clamav clamav-daemon
  elif command -v dnf     >/dev/null 2>&1; then dnf install -y epel-release || true; dnf install -y clamav clamav-update
  elif command -v yum     >/dev/null 2>&1; then yum install -y epel-release || true; yum install -y clamav clamav-update
  elif command -v zypper  >/dev/null 2>&1; then zypper -n install clamav
  else echo "Install ClamAV manually, then re-run"; exit 1; fi
fi

echo "[2/5] Signatures"
if systemctl list-unit-files 2>/dev/null | grep -q '^clamav-freshclam'; then
  systemctl stop clamav-freshclam 2>/dev/null || true
  freshclam || true
  systemctl enable --now clamav-freshclam 2>/dev/null || true
  systemctl enable --now clamav-daemon    2>/dev/null || true
else
  [ -f /etc/freshclam.conf ] && sed -i 's/^Example/#Example/' /etc/freshclam.conf
  freshclam || true
fi

echo "[3/5] Scripts -> $BIN"
for f in isolate.sh deisolate.sh isolation-watchdog.sh wazuh-av-scan.sh firewall-check.sh; do
  install -m 0750 -o root -g root "$SRC/$f" "$BIN/$f"
done
touch $W/logs/wazuh-av.log; chmod 640 $W/logs/wazuh-av.log

echo "[4/5] Agent config + watchdog service"
if ! grep -q 'WAZUH-ISOLATION BEGIN' $W/etc/ossec.conf; then
cat >> $W/etc/ossec.conf <<'EOF'
<!-- WAZUH-ISOLATION BEGIN -->
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/wazuh-av.log</location>
  </localfile>
  <wodle name="command">
    <disabled>no</disabled>
    <tag>av-recent</tag>
    <command>/var/ossec/active-response/bin/wazuh-av-scan.sh recent</command>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>
    <ignore_output>yes</ignore_output>
    <timeout>900</timeout>
  </wodle>
  <wodle name="command">
    <disabled>no</disabled>
    <tag>av-full</tag>
    <command>/var/ossec/active-response/bin/wazuh-av-scan.sh full</command>
    <interval>7d</interval>
    <run_on_start>no</run_on_start>
    <ignore_output>yes</ignore_output>
    <timeout>0</timeout>
  </wodle>
</ossec_config>
<!-- WAZUH-ISOLATION END -->
EOF
fi
cat > /etc/systemd/system/wazuh-isolation-watchdog.service <<'EOF'
[Unit]
Description=Wazuh isolation watchdog (releases the endpoint after the isolation time)
After=local-fs.target

[Service]
ExecStart=/var/ossec/active-response/bin/isolation-watchdog.sh
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now wazuh-isolation-watchdog

if ! grep -q 'WAZUH-FWCHECK BEGIN' /var/ossec/etc/ossec.conf; then
cat >> /var/ossec/etc/ossec.conf <<'EOF'
<!-- WAZUH-FWCHECK BEGIN -->
<ossec_config>
  <localfile>
    <log_format>command</log_format>
    <alias>fw-check</alias>
    <command>/var/ossec/active-response/bin/firewall-check.sh</command>
    <frequency>600</frequency>
  </localfile>
</ossec_config>
<!-- WAZUH-FWCHECK END -->
EOF
fi

echo "[5/5] Restart agent"
systemctl restart wazuh-agent
echo "Done. Status: systemctl status wazuh-isolation-watchdog"
