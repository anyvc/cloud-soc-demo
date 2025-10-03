# generate-cloud-logs.ps1
Param(
  [string]$OutPath = "logs/synthetic-cloudtrail.json",
  [int]$Count = 10
)

# sample event names: benign + suspicious
$benignEvents = @("ListBuckets","GetObject","DescribeInstances","StartInstances")
$maliciousEvents = @("DeleteBucket","CreateUser","ConsoleLogin")

# sample IPs
$ips = @("198.51.100.22","203.0.113.45","192.0.2.10","10.0.5.4","172.16.0.12")

$records = @()

for ($i=0; $i -lt $Count; $i++) {
    $isSuspicious = (Get-Random -Minimum 0 -Maximum 100) -lt 30  # ~30% suspicious
    if ($isSuspicious) {
        $eventName = Get-Random $maliciousEvents
    } else {
        $eventName = Get-Random $benignEvents
    }

    $record = [pscustomobject]@{
        eventVersion     = "1.05"
        eventTime        = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        eventName        = $eventName
        userIdentity     = @{ userName = ("user" + (Get-Random -Minimum 1 -Maximum 5)) }
        sourceIPAddress  = (Get-Random $ips)
        awsRegion        = "us-east-1"
        requestParameters= @{}
    }

    $records += $record
}

$log = @{ Records = $records }

# ensure directory exists
New-Item -ItemType Directory -Path (Split-Path $OutPath) -Force | Out-Null
$log | ConvertTo-Json -Depth 5 | Set-Content -Path $OutPath -Encoding UTF8

Write-Output "Generated $Count synthetic events -> $OutPath"
