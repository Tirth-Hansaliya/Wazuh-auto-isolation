# Manual de-isolation (same logic as Wazuh's "delete"). Usage: .\deisolate.ps1 [-Reason text]
param([string]$Reason = "manual")
& (Join-Path $PSScriptRoot "isolate.ps1") -Action delete -Reason $Reason
