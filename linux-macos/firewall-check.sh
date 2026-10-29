#!/bin/sh
# Manual de-isolation (same logic as Wazuh's "delete"). Usage: deisolate.sh [reason]
exec "$(dirname "$0")/isolate.sh" delete "${1:-manual}"
root@studen:/var/ossec/active-response/bin# cat firewall
firewall-check.sh  firewalld-drop     firewall-drop      
root@studen:/var/ossec/active-response/bin# cat firewall-check.sh 
#!/bin/sh
# firewall-check.sh - run by the Wazuh agent (localfile command).
#   prints "fw-check: FIREWALL_OFF ..." every run while the host firewall is OFF
#   prints "fw-check: FIREWALL_ON ..."  ONCE, when the firewall goes from OFF back to ON
#   prints nothing while the firewall stays ON (no noise)
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
have() { command -v "$1" >/dev/null 2>&1; }

STATE="${FWCHECK_STATE:-/var/ossec/var/run/fw-check.state}"
mkdir -p "$(dirname "$STATE")" 2>/dev/null

# detect: sets OS and FW_STATE (on|off) and TYPE
detect() {
  if [ "$(uname -s)" = "Darwin" ]; then
    OS=macos; TYPE=application-firewall
    out=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
    case "$out" in *"disabled"*|*"State = 0"*) FW_STATE=off ;; *) FW_STATE=on ;; esac
    return
  fi
  OS=linux; FW_STATE=on
  if have systemctl && systemctl is-active --quiet firewalld 2>/dev/null; then TYPE=firewalld; return; fi
  # Ubuntu/Debian: if ufw is installed, ufw alone decides (so 'ufw disable' is enough to alert,
  # even if Docker/fail2ban/leftover iptables or nft rules still exist)
  if have ufw; then
    if ufw status 2>/dev/null | grep -q '^Status: active'; then TYPE=ufw; return; fi
    FW_STATE=off; TYPE=ufw-inactive; return
  fi
  if have iptables; then
    n=$(iptables -S 2>/dev/null | grep -v -e '^-P' -e '^-N' -e WAZUH_ISO | wc -l)
    [ "$n" -gt 0 ] && { TYPE=iptables; return; }
    iptables -S 2>/dev/null | grep -q -E '^-P INPUT (DROP|REJECT)' && { TYPE=iptables; return; }
  fi
  if have nft; then
    n=$(nft list ruleset 2>/dev/null | awk '/^table/ {skip = ($3 == "wazuh_isolate")} !skip && /(accept|drop|reject)( |$)/ {c++} END {print c+0}')
    [ "$n" -gt 0 ] && { TYPE=nftables; return; }
  fi
  FW_STATE=off; TYPE=no-active-rules
}

detect
prev=$(cat "$STATE" 2>/dev/null)

if [ "$FW_STATE" = "off" ]; then
  echo "fw-check: FIREWALL_OFF os=$OS type=$TYPE"
else
  [ "$prev" = "off" ] && echo "fw-check: FIREWALL_ON os=$OS type=$TYPE (firewall re-enabled)"
fi
echo "$FW_STATE" > "$STATE" 2>/dev/null
exit 0
