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
