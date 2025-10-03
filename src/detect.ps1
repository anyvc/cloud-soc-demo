# detect.ps1
Param([string]$LogPath = "logs/sample-cloudtrail.json", [string]$OutAlerts = "alerts/alerts.json")

if (-not (Test-Path $LogPath)) { Write-Error "Log not found: $LogPath"; exit 2 }

$json = Get-Content $LogPath -Raw | ConvertFrom-Json
$alerts = @()

foreach ($event in $json.Records) {
  if ($event.eventName -in @("CreateUser","DeleteBucket","ConsoleLogin")) {
    $alerts += [pscustomobject]@{
      Time = $event.eventTime
      Event = $event.eventName
      User = ($event.userIdentity.userName)
      IP = $event.sourceIPAddress
      Note = "suspicious event matched basic rule"
    }
  }
}

# ensure alerts folder exists
New-Item -ItemType Directory -Path (Split-Path $OutAlerts) -Force | Out-Null
$alerts | ConvertTo-Json -Depth 5 | Set-Content -Path $OutAlerts

# console summary for quick verification
if ($alerts.Count -gt 0) {
  Write-Output "ALERTS FOUND: $($alerts.Count)"
  $alerts | Format-Table -AutoSize
} else {
  Write-Output "No alerts"
}
