#!/bin/sh
# isolation-watchdog.sh - the ONLY thing that releases an isolated endpoint.
# Runs as a system service (systemd on Linux, launchd on macOS). Checks once a
# second, so release happens 120-121 s after isolation. Survives reboots,
# agent restarts and Wazuh timeouts because it only reads the state files.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
OS=$(uname -s)
if [ -z "$ISO_HOME" ]; then
  if [ "$OS" = "Darwin" ]; then ISO_HOME=/Library/Ossec; else ISO_HOME=/var/ossec; fi
fi
STATE="$ISO_HOME/var/isolation"
ISO="$ISO_HOME/active-response/bin/isolate.sh"
mkdir -p "$STATE"

"$ISO" cleanup                      # remove orphaned rules left by a crash/reboot
while :; do
  if [ -f "$STATE/release_at" ]; then
    r=$(cat "$STATE/release_at" 2>/dev/null)
    case "$r" in
      ''|*[!0-9]*) ;;                                   # half-written file: ignore this round
      *) [ "$(date +%s)" -ge "$r" ] && "$ISO" delete watchdog ;;
    esac
  fi
  sleep 1
done
root@studen:/var/ossec/active-response/bin# cat wazuh-av-scan.sh 
#!/bin/sh
# =============================================================================
# wazuh-av-scan.sh - system-wide ClamAV scan for Linux and macOS
#   recent : files created/changed in the last AV_RECENT_MIN minutes (every 5 min)
#   full   : every file on the system (weekly)
#   update : refresh signatures (macOS; Linux uses the clamav-freshclam service)
# Detections are written in syslog format to <wazuh>/logs/wazuh-av.log, which the
# agent forwards; manager rule 100230 turns them into alerts that trigger isolation.
# =============================================================================
MODE="${1:-recent}"
RECENT_MIN="${AV_RECENT_MIN:-10}"
QUARANTINE="${AV_QUARANTINE:-yes}"     # yes = move detected files to <wazuh>/quarantine (stops repeat alerts)
MAXSIZE_K="${AV_MAXSIZE_K:-102400}"    # skip files bigger than 100 MB

PATH=/opt/homebrew/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
OS=$(uname -s)
if [ -z "$ISO_HOME" ]; then
  if [ "$OS" = "Darwin" ]; then ISO_HOME=/Library/Ossec; else ISO_HOME=/var/ossec; fi
fi
LOG="$ISO_HOME/logs/wazuh-av.log"
QDIR="$ISO_HOME/quarantine"
WORK="$ISO_HOME/var/av"
LOCKD="$WORK/$MODE.lock.d"
mkdir -p "$WORK" "$ISO_HOME/logs"

have() { command -v "$1" >/dev/null 2>&1; }
log()  { printf '%s %s wazuh-av: %s\n' "$(date '+%b %e %H:%M:%S')" "$(hostname -s 2>/dev/null || hostname)" "$*" >> "$LOG"; }

if [ "$MODE" = update ]; then
  if [ "$OS" = Darwin ] && have freshclam; then freshclam --quiet >/dev/null 2>&1; fi
  exit 0
fi

# one run of each mode at a time (stale lock after 12 h is removed)
if [ -d "$LOCKD" ] && [ -n "$(find "$LOCKD" -maxdepth 0 -mmin +720 2>/dev/null)" ]; then rmdir "$LOCKD"; fi
mkdir "$LOCKD" 2>/dev/null || exit 0
trap 'rmdir "$LOCKD" 2>/dev/null; rm -f "$WORK/$MODE.list" "$WORK/$MODE.out"' EXIT INT TERM

if ! have clamscan && ! have clamdscan; then log "ERROR ClamAV is not installed"; exit 1; fi

AGE=""; [ "$MODE" = recent ] && AGE="-cmin -$RECENT_MIN"    # ctime cannot be faked, unlike mtime

find_files() {
  if [ "$OS" = Darwin ]; then
    find / \( -path /dev -o -path /Volumes -o -path /System/Volumes -o -path /private/var/vm \
           -o -path "$ISO_HOME/logs" -o -path "$ISO_HOME/var" -o -path "$QDIR" \
           -o -path /opt/homebrew/var/lib/clamav -o -path /usr/local/var/lib/clamav \) -prune \
           -o -type f $AGE -size -"${MAXSIZE_K}k" -print 2>/dev/null
  else
    find / \( -path /proc -o -path /sys -o -path /dev -o -path /run \
           -o -path "$ISO_HOME/logs" -o -path "$ISO_HOME/var" -o -path "$QDIR" \
           -o -path /var/lib/clamav \) -prune \
           -o -type f $AGE -size -"${MAXSIZE_K}k" -print 2>/dev/null
  fi
}

find_files > "$WORK/$MODE.list"
COUNT=$(wc -l < "$WORK/$MODE.list" | tr -d ' ')
if [ "$COUNT" -eq 0 ]; then log "SCAN-DONE mode=$MODE files=0 detections=0"; exit 0; fi

if have clamdscan && clamdscan --ping 1 >/dev/null 2>&1; then
  clamdscan --fdpass --no-summary -f "$WORK/$MODE.list" > "$WORK/$MODE.out" 2>/dev/null
else
  nice -n 19 clamscan --no-summary -i -f "$WORK/$MODE.list" > "$WORK/$MODE.out" 2>/dev/null
fi

DET=0
while IFS= read -r line; do
  path=${line%: * FOUND}
  sig=${line##*: }; sig=${sig% FOUND}
  act=none
  if [ "$QUARANTINE" = yes ] && [ -f "$path" ]; then
    mkdir -p "$QDIR" && chmod 700 "$QDIR"
    safe=$(basename "$path" | tr -c 'A-Za-z0-9._-' '_')
    dest="$QDIR/$(date +%s)_$safe"
    if mv -f -- "$path" "$dest" 2>/dev/null; then chmod 000 "$dest" 2>/dev/null; act=quarantined
    else act=quarantine-failed; fi
  fi
  log "DETECTED sig=$sig action=$act path=$path"
  DET=$((DET+1))
done <<EOF_LINES
$(grep ' FOUND$' "$WORK/$MODE.out")
EOF_LINES

log "SCAN-DONE mode=$MODE files=$COUNT detections=$DET"
