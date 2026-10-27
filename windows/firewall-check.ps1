# firewall-check.ps1 - prints "fw-check: FIREWALL_OFF ..." when a Windows Firewall profile is disabled.
# Run by the Wazuh agent (localfile command). Prints nothing when all profiles are on.
$off = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
if ($off.Count) { "fw-check: FIREWALL_OFF os=windows profiles=$($off -join ',')" }
