#!/bin/sh
# firewall-check.sh - prints one line "fw-check: FIREWALL_OFF ..." when the host firewall is off.
# Run by the Wazuh agent (localfile command). Prints nothing when the firewall is on.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
have() { command -v "$1" >/dev/null 2>&1; }

if [ "$(uname -s)" = "Darwin" ]; then
  out=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
  case "$out" in *"disabled"*|*"State = 0"*) echo "fw-check: FIREWALL_OFF os=macos type=application-firewall" ;; esac
  exit 0
fi

# Linux: firewalld or ufw active?
if have systemctl && systemctl is-active --quiet firewalld 2>/dev/null; then exit 0; fi
if have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then exit 0; fi

# iptables: any rule or a DROP/REJECT policy (our own WAZUH_ISO chains do not count)
if have iptables; then
  n=$(iptables -S 2>/dev/null | grep -v -e '^-P' -e '^-N' -e WAZUH_ISO | wc -l)
  [ "$n" -gt 0 ] && exit 0
  iptables -S 2>/dev/null | grep -q -E '^-P INPUT (DROP|REJECT)' && exit 0
fi
# nftables: any accept/drop/reject rule outside our wazuh_isolate table
if have nft; then
  n=$(nft list ruleset 2>/dev/null | awk '/^table/ {skip = ($3 == "wazuh_isolate")} !skip && /(accept|drop|reject)( |$)/ {c++} END {print c+0}')
  [ "$n" -gt 0 ] && exit 0
fi
echo "fw-check: FIREWALL_OFF os=linux type=no-active-rules"
