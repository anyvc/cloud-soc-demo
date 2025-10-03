# detect.ps1
Param(
  [string]$LogPath = "logs/synthetic-cloudtrail.json",
  [string]$OutAlerts = "alerts/alerts.json"
)

if (-not (Test-Path $LogPath)) {
    Write-Error "Log not found: $LogPath"
    exit 2
}

$json = Get-Content $LogPath -Raw | ConvertFrom-Json
$alerts = @()

foreach ($event in $json.Records) {
    # rule: suspicious event types
    if ($event.eventName -in @("CreateUser","DeleteBucket","ConsoleLogin")) {
        $alerts += [pscustomobject]@{
            id       = [guid]::NewGuid().ToString()
            time     = $event.eventTime
            event    = $event.eventName
            user     = $event.userIdentity.userName
            ip       = $event.sourceIPAddress
            severity = "High"
            category = "IAM"
            note     = "Suspicious event type"
        }
    }

    # rule: private IPs (cloud logs usually public IPs)
    if ($event.sourceIPAddress -match '^(10\.|172\.16\.|192\.168\.)') {
        $alerts += [pscustomobject]@{
            id       = [guid]::NewGuid().ToString()
            time     = $event.eventTime
            event    = $event.eventName
            user     = $event.userIdentity.userName
            ip       = $event.sourceIPAddress
            severity = "Medium"
            category = "Networking"
            note     = "Unusual private IP source"
        }
    }
}

# output folder
New-Item -ItemType Directory -Path (Split-Path $OutAlerts) -Force | Out-Null
$alerts | ConvertTo-Json -Depth 5 | Set-Content -Path $OutAlerts -Encoding UTF8

# console summary
if ($alerts.Count -gt 0) {
    Write-Output "==== ALERT SUMMARY ===="
    $alerts | Select-Object time,event,user,ip,severity,note | Format-Table -AutoSize
    Write-Output "Saved alerts -> $OutAlerts"
} else {
    Write-Output "No alerts found"
}
