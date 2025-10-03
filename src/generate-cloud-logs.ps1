# generate-cloud-logs.ps1
Param([string]$OutPath = "logs/sample-cloudtrail.json")

# For Phase 1: we already have the sample log, so just confirm it's there.
if (Test-Path $OutPath) {
    Write-Output "Using existing sample log at $OutPath"
} else {
    Write-Error "Log not found at $OutPath — please add logs/sample-cloudtrail.json"
}
