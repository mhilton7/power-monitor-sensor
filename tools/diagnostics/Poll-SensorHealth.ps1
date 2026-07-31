[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SensorUrl,
    [ValidateRange(1, 1440)]
    [int]$DurationMinutes = 30,
    [ValidateRange(5, 300)]
    [int]$IntervalSeconds = 5,
    [string]$OutputPath = (Join-Path $PWD ("sensor-health-{0}.jsonl" -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
)

$monitor = Join-Path $PSScriptRoot 'Monitor-TwoSensors.ps1'
& $monitor -SensorUrls @($SensorUrl) -DurationMinutes $DurationMinutes `
    -IntervalSeconds $IntervalSeconds -OutputPath $OutputPath
