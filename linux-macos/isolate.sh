#!/bin/sh
# =============================================================================
# isolate.sh - Wazuh Active Response: network isolation for Linux and macOS
#
#   add      isolate the endpoint   (Wazuh calls this, JSON on stdin)
#   delete   release the endpoint
#   cleanup  remove stray isolation rules if the endpoint is NOT isolated
#   status   show current state
#
# Release is done by isolation-watchdog.sh (a system service), NOT by Wazuh's
# <timeout>. State lives in <wazuh>/var/isolation so a reboot or agent restart
# can never leave the endpoint isolated.
# =============================================================================

# ------------------------------ Tunables ------------------------------------
DURATION="${ISO_DURATION:-120}"       # seconds the endpoint stays isolated
COOLDOWN="${ISO_COOLDOWN:-300}"       # seconds after release in which new alerts are ignored
EXTRA_ALLOW="${ISO_EXTRA_ALLOW:-}"    # space-separated IPs that stay reachable (admin jump host)
MANAGER_IPS="${ISO_MANAGER_IPS:-}"    # empty = auto-detect from ossec.conf
DRY_RUN="${ISO_DRY_RUN:-0}"           # 1 = change state/logs only, never touch the firewall
# ----------------------------------------------------------------------------

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
OS=$(uname -s)
if [ -z "$ISO_HOME" ]; then
  if [ "$OS" = "Darwin" ]; then ISO_HOME=/Library/Ossec; else ISO_HOME=/var/ossec; fi
fi
STATE="$ISO_HOME/var/isolation"
LOG="$ISO_HOME/logs/active-responses.log"
LOCKD="$STATE/lock.d"
mkdir -p "$STATE" "$ISO_HOME/logs" 2>/dev/null
chmod 700 "$STATE" 2>/dev/null

log()  { printf '%s active-response/bin/isolate: %s\n' "$(date '+%Y/%m/%d %H:%M:%S')" "$*" >> "$LOG"; }
now()  { date +%s; }
have() { command -v "$1" >/dev/null 2>&1; }
num()  { v=$(cat "$1" 2>/dev/null); case "$v" in ''|*[!0-9]*) echo 0;; *) echo "$v";; esac; }

# ---- Parse the action (argument, or Wazuh JSON on stdin) -------------------
ACTION="$1"; REASON="${2:-wazuh}"; RULE=""
if [ -z "$ACTION" ] && [ ! -t 0 ]; then
  read -r JSON
  if printf '%s' "$JSON" | grep -q '"command" *: *"delete"'; then ACTION=delete; else ACTION=add; fi
  RULE=$(printf '%s' "$JSON" | grep -o '"rule":{[^}]*}' | grep -o '"id":"[0-9]*"' | head -1 | cut -d'"' -f4)
fi
RULE="${RULE:-manual}"

# ---- Lock (mkdir is atomic on Linux and macOS) ------------------------------
lock() {
  n=0
  until mkdir "$LOCKD" 2>/dev/null; do
    n=$((n+1)); [ "$n" -ge 30 ] && rmdir "$LOCKD" 2>/dev/null   # break a stale lock
    sleep 1
  done
  trap 'rmdir "$LOCKD" 2>/dev/null' EXIT INT TERM
}

# ---- Which IPs must stay reachable ------------------------------------------
resolve_host() {
  if [ "$OS" = "Darwin" ]; then
    dscacheutil -q host -a name "$1" 2>/dev/null | awk '/^ip_address:/{print $2}'
  else
    getent ahosts "$1" 2>/dev/null | awk '{print $1}' | sort -u
  fi
}
get_ips() {
  if [ -n "$MANAGER_IPS" ]; then list="$MANAGER_IPS"
  else
    list=$(sed 's/<!--.*-->//g' "$ISO_HOME/etc/ossec.conf" 2>/dev/null \
           | grep -o '<address>[^<]*</address>' | sed 's/<[^>]*>//g' | tr -d ' ')
  fi
  for h in $list $EXTRA_ALLOW; do
    case "$h" in
      *:*)           echo "$h" ;;              # IPv6 literal
      *[!0-9.]*)     resolve_host "$h" ;;      # hostname
      *)             echo "$h" ;;              # IPv4 literal
    esac
  done | grep -E '^[0-9a-fA-F:.]+$' | sort -u
}

# ---- Backend: nftables (preferred, own table, atomic) -----------------------
nft_apply() {
  f="$STATE/nft-isolate.conf"; v4=""; v6=""
  for ip in $1; do case "$ip" in *:*) v6="$v6 $ip";; *) v4="$v4 $ip";; esac; done
  {
    echo "table inet wazuh_isolate {"
    for dir in in out; do
      if [ "$dir" = in ]; then hook=input;  m=saddr; ifc=iifname
      else                     hook=output; m=daddr; ifc=oifname; fi
      echo "  chain isolate_$dir {"
      echo "    type filter hook $hook priority -400; policy accept;"
      echo "    $ifc \"lo\" accept"
      for ip in $v4; do echo "    ip $m $ip accept"; done
      for ip in $v6; do echo "    ip6 $m $ip accept"; done
      if [ -n "$v6" ]; then
        echo "    icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept"
      fi
      echo "    drop"
      echo "  }"
    done
    echo "  chain isolate_fwd {"
    echo "    type filter hook forward priority -400; policy accept;"
    echo "    drop"
    echo "  }"
    echo "}"
  } > "$f"
  nft delete table inet wazuh_isolate 2>/dev/null
  nft -f "$f"
}
nft_remove() { nft delete table inet wazuh_isolate 2>/dev/null; rm -f "$STATE/nft-isolate.conf"; }

# ---- Backend: iptables / ip6tables (fallback) -------------------------------
ipt_remove_family() {
  T=$1; have "$T" || return 0
  for pair in "INPUT WAZUH_ISO_IN" "OUTPUT WAZUH_ISO_OUT" "FORWARD WAZUH_ISO_FWD"; do
    set -- $pair
    while $T -D "$1" -j "$2" 2>/dev/null; do :; done
    $T -F "$2" 2>/dev/null; $T -X "$2" 2>/dev/null
  done
}
ipt_apply_family() {            # $1 = iptables|ip6tables, rest = manager IPs of that family
  T=$1; shift
  have "$T" || return 0
  ipt_remove_family "$T"
  $T -N WAZUH_ISO_IN && $T -N WAZUH_ISO_OUT && $T -N WAZUH_ISO_FWD || return 1
  $T -A WAZUH_ISO_IN  -i lo -j ACCEPT
  $T -A WAZUH_ISO_OUT -o lo -j ACCEPT
  for ip in "$@"; do
    $T -A WAZUH_ISO_IN  -s "$ip" -j ACCEPT
    $T -A WAZUH_ISO_OUT -d "$ip" -j ACCEPT
  done
  if [ "$T" = ip6tables ] && [ "$#" -gt 0 ]; then
    $T -A WAZUH_ISO_IN -p ipv6-icmp -j ACCEPT; $T -A WAZUH_ISO_OUT -p ipv6-icmp -j ACCEPT
  fi
  $T -A WAZUH_ISO_IN -j DROP; $T -A WAZUH_ISO_OUT -j DROP; $T -A WAZUH_ISO_FWD -j DROP
  $T -I INPUT 1 -j WAZUH_ISO_IN && $T -I OUTPUT 1 -j WAZUH_ISO_OUT && $T -I FORWARD 1 -j WAZUH_ISO_FWD
}
ipt_apply() {
  v4=$(printf '%s\n' "$1" | grep -v ':'); v6=$(printf '%s\n' "$1" | grep ':')
  ipt_apply_family iptables $v4 && ipt_apply_family ip6tables $v6
}

# ---- Backend: macOS pf ------------------------------------------------------
pf_apply() {
  f="$STATE/pf-isolate.conf"
  {
    echo "set skip on lo0"
    echo "block drop all"
    for ip in $1; do
      case "$ip" in
        *:*) echo "pass quick inet6 from any to $ip keep state"; echo "pass quick inet6 from $ip to any keep state" ;;
        *)   echo "pass quick inet from any to $ip keep state";  echo "pass quick inet from $ip to any keep state" ;;
      esac
    done
  } > "$f"
  tok=$(pfctl -E 2>&1 | awk '/Token/ {print $NF}')
  [ -n "$tok" ] && echo "$tok" > "$STATE/pf_token"
  pfctl -f "$f" >/dev/null 2>&1 || return 1
  pfctl -F states >/dev/null 2>&1            # kill existing connections
  return 0
}
pf_remove() {
  pfctl -f /etc/pf.conf >/dev/null 2>&1      # restore the normal ruleset
  if [ -f "$STATE/pf_token" ]; then pfctl -X "$(cat "$STATE/pf_token")" >/dev/null 2>&1; fi
  rm -f "$STATE/pf_token" "$STATE/pf-isolate.conf"
}

# ---- Dispatcher --------------------------------------------------------------
apply_rules() {
  if [ "$DRY_RUN" = 1 ]; then log "DRY-RUN: firewall NOT changed (would allow: $(echo $1))"; return 0; fi
  if [ "$OS" = "Darwin" ]; then have pfctl && pf_apply "$1"
  elif have nft;      then nft_apply "$1"
  elif have iptables; then ipt_apply "$1"
  else log "ERROR no firewall tool found (need nft or iptables)"; return 1; fi
}
remove_rules() {
  [ "$DRY_RUN" = 1 ] && return 0
  if [ "$OS" = "Darwin" ]; then
    if [ -f "$STATE/pf-isolate.conf" ] || [ -f "$STATE/pf_token" ]; then pf_remove; fi
  else
    have nft && nft_remove
    have iptables && ipt_remove_family iptables
    have ip6tables && ipt_remove_family ip6tables
  fi
  return 0
}

# ---- State machine -------------------------------------------------------------
release_now() {                     # caller holds the lock; $1 = reason
  was=0; [ -f "$STATE/release_at" ] && was=1
  remove_rules
  if [ "$was" = 1 ]; then
    t=$(now); st=$(num "$STATE/isolated_at"); [ "$st" -eq 0 ] && st=$t
    rm -f "$STATE/isolated_at" "$STATE/release_at"
    echo "$t" > "$STATE/released_at"
    log "RELEASED endpoint, network restored after $((t-st))s ($1)"
  fi
}

do_add() {
  lock
  t=$(now)
  rel=$(num "$STATE/release_at")
  if [ -f "$STATE/release_at" ]; then
    if [ "$rel" -gt 0 ] && [ "$t" -lt "$rel" ]; then
      log "IGNORED alert rule=$RULE: already isolated, release in $((rel-t))s (timer not extended)"
      return 0
    fi
    release_now "expired, self-heal"           # watchdog was not running
  fi
  last=$(num "$STATE/released_at")
  if [ "$last" -gt 0 ] && [ $((t-last)) -lt "$COOLDOWN" ]; then
    log "SUPPRESSED alert rule=$RULE: cooldown, $((COOLDOWN-(t-last)))s left (prevents isolation loops)"
    return 0
  fi
  ips=$(get_ips)
  if [ -z "$ips" ]; then log "ABORT endpoint NOT isolated: manager IP not found"; return 1; fi
  if apply_rules "$ips"; then
    echo "$t" > "$STATE/isolated_at"
    echo $((t+DURATION)) > "$STATE/release_at.tmp" && mv -f "$STATE/release_at.tmp" "$STATE/release_at"
    rm -f "$STATE/released_at"
    log "ISOLATED endpoint for ${DURATION}s rule=$RULE allowed=$(echo $ips | tr ' ' ',')"
  else
    remove_rules
    log "ERROR failed to apply isolation rules, endpoint NOT isolated"
    return 1
  fi
}
do_delete()  { lock; release_now "$REASON"; }
do_cleanup() { lock; [ -f "$STATE/release_at" ] || remove_rules; }
do_status()  {
  if [ -f "$STATE/release_at" ]; then echo "ISOLATED, release in $(( $(num "$STATE/release_at") - $(now) ))s"
  else echo "not isolated"; fi
}

case "$ACTION" in
  add)     do_add; exit $? ;;
  delete)  do_delete; exit 0 ;;
  cleanup) do_cleanup; exit 0 ;;
  status)  do_status; exit 0 ;;
  *)       echo "usage: $0 add|delete|cleanup|status"; exit 2 ;;
esac
