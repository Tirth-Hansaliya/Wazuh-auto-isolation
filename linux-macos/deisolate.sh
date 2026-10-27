#!/bin/sh
# Manual de-isolation (same logic as Wazuh's "delete"). Usage: deisolate.sh [reason]
exec "$(dirname "$0")/isolate.sh" delete "${1:-manual}"
