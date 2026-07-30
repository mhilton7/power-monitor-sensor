[CmdletBinding()]
param(
    [string]$Address = "192.168.0.26",
    [ValidateRange(1, 10000)]
    [int]$TargetHeartbeatIntervals = 100,
    [ValidateRange(1, 60)]
    [int]$PollSeconds = 2,
    [ValidateRange(2, 5)]
    [int]$PingAttempts = 3,
    [ValidateRange(1, 48)]
    [int]$TimeoutHours = 8,
    [string]$OutputDirectory = ".test-tmp\heartbeat-soak"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Net.Http

$resolvedOutput = [System.IO.Path]::GetFullPath(
    (Join-Path (Get-Location) $OutputDirectory)
)
[System.IO.Directory]::CreateDirectory($resolvedOutput) | Out-Null
$stamp = [DateTime]::UtcNow.ToString("yyyyMMdd-HHmmss")
$csvPath = Join-Path $resolvedOutput "heartbeat-soak-$stamp.csv"
$summaryPath = Join-Path $resolvedOutput "heartbeat-soak-$stamp.summary.json"
$rootUri = "http://$Address/"
$healthUri = "http://$Address/api/local/health"
$deadline = [DateTime]::UtcNow.AddHours($TimeoutHours)

$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.UseProxy = $false
$client = [System.Net.Http.HttpClient]::new($handler)
$client.Timeout = [TimeSpan]::FromSeconds(3)
$pingProbe = [System.Net.NetworkInformation.Ping]::new()

$firstHealth = $null
$lastHealth = $null
$previousUptime = $null
$resetCount = 0
$pingFailures = 0
$webFailures = 0
$healthFailures = 0
$wifiFailures = 0
$storageFailures = 0
$samples = 0
$minimumStackMargin = 100
$minimumFreeInternal = [uint64]::MaxValue
$minimumLargestInternal = [uint64]::MaxValue
$completed = $false

function Invoke-BoundedGet {
    param([string]$Uri)
    try {
        $response = $client.GetAsync($Uri).GetAwaiter().GetResult()
        try {
            $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            return [pscustomobject]@{
                Ok = $response.IsSuccessStatusCode
                Status = [int]$response.StatusCode
                Body = $body
            }
        }
        finally {
            $response.Dispose()
        }
    }
    catch {
        return [pscustomobject]@{ Ok = $false; Status = 0; Body = "" }
    }
}

try {
    while ([DateTime]::UtcNow -lt $deadline) {
        $timestamp = [DateTime]::UtcNow.ToString("o")
        $pingOk = $false
        $pingSuccesses = 0
        for ($pingAttempt = 1; $pingAttempt -le $PingAttempts; $pingAttempt++) {
            try {
                $pingReply = $pingProbe.Send($Address, 400)
                if ($pingReply.Status -eq
                    [System.Net.NetworkInformation.IPStatus]::Success) {
                    $pingSuccesses++
                    $pingOk = $true
                    break
                }
            }
            catch {
                # The sample fails only if every bounded ICMP attempt fails.
            }
        }
        if (-not $pingOk) {
            $pingFailures++
        }

        $root = Invoke-BoundedGet -Uri $rootUri
        if (-not $root.Ok) {
            $webFailures++
        }
        $healthResponse = Invoke-BoundedGet -Uri $healthUri
        $health = $null
        if ($healthResponse.Ok) {
            try {
                $health = $healthResponse.Body | ConvertFrom-Json
            }
            catch {
                $health = $null
            }
        }
        if ($null -eq $health) {
            $healthFailures++
        }
        else {
            if (-not [bool]$health.wifi_connected) {
                $wifiFailures++
            }
            if (-not [bool]$health.storage_writable) {
                $storageFailures++
            }
            if ($null -eq $firstHealth) {
                $firstHealth = $health
            }
            if ($null -ne $previousUptime -and
                [uint64]$health.uptime_seconds -lt [uint64]$previousUptime) {
                $resetCount++
            }
            $previousUptime = [uint64]$health.uptime_seconds
            $lastHealth = $health
            $minimumStackMargin = [Math]::Min(
                $minimumStackMargin, [int]$health.stack_margin_percent
            )
            $minimumFreeInternal = [Math]::Min(
                $minimumFreeInternal, [uint64]$health.free_internal_heap_bytes
            )
            $minimumLargestInternal = [Math]::Min(
                $minimumLargestInternal,
                [uint64]$health.largest_internal_block_bytes
            )
        }

        $row = [ordered]@{
            timestamp_utc = $timestamp
            ping_ok = $pingOk
            ping_attempts = $PingAttempts
            ping_successes = $pingSuccesses
            webui_ok = $root.Ok
            webui_status = $root.Status
            health_ok = $null -ne $health
            uptime_seconds = if ($health) { $health.uptime_seconds } else { "" }
            wifi_connected = if ($health) { $health.wifi_connected } else { "" }
            sync_in_progress = if ($health) { $health.sync_in_progress } else { "" }
            sync_pending = if ($health) { $health.sync_pending } else { "" }
            heartbeat_successes = if ($health) { $health.heartbeat_successes } else { "" }
            heartbeat_failures = if ($health) { $health.heartbeat_failures } else { "" }
            stack_high_water_bytes = if ($health) { $health.stack_high_water_bytes } else { "" }
            stack_margin_percent = if ($health) { $health.stack_margin_percent } else { "" }
            free_heap_bytes = if ($health) { $health.free_heap_bytes } else { "" }
            free_internal_heap_bytes = if ($health) { $health.free_internal_heap_bytes } else { "" }
            largest_internal_block_bytes = if ($health) { $health.largest_internal_block_bytes } else { "" }
            storage_writable = if ($health) { $health.storage_writable } else { "" }
            meter_healthy = if ($health) { $health.meter_healthy } else { "" }
        }
        [pscustomobject]$row | Export-Csv -LiteralPath $csvPath `
            -NoTypeInformation -Append
        $samples++

        if ($null -ne $firstHealth -and $null -ne $lastHealth) {
            $firstAttempts =
                [uint64]$firstHealth.heartbeat_successes +
                [uint64]$firstHealth.heartbeat_failures
            $lastAttempts =
                [uint64]$lastHealth.heartbeat_successes +
                [uint64]$lastHealth.heartbeat_failures
            if (($lastAttempts - $firstAttempts) -ge $TargetHeartbeatIntervals) {
                $completed = $true
                break
            }
        }
        Start-Sleep -Seconds $PollSeconds
    }
}
finally {
    $pingProbe.Dispose()
    $client.Dispose()
    $handler.Dispose()
}

$heartbeatDelta = 0
$successDelta = 0
$failureDelta = 0
if ($null -ne $firstHealth -and $null -ne $lastHealth) {
    $successDelta =
        [uint64]$lastHealth.heartbeat_successes -
        [uint64]$firstHealth.heartbeat_successes
    $failureDelta =
        [uint64]$lastHealth.heartbeat_failures -
        [uint64]$firstHealth.heartbeat_failures
    $heartbeatDelta = $successDelta + $failureDelta
}
$passed =
    $completed -and
    $resetCount -eq 0 -and
    $pingFailures -eq 0 -and
    $webFailures -eq 0 -and
    $healthFailures -eq 0 -and
    $wifiFailures -eq 0 -and
    $storageFailures -eq 0 -and
    $minimumStackMargin -ge 25

$summary = [ordered]@{
    completed_utc = [DateTime]::UtcNow.ToString("o")
    address = $Address
    target_heartbeat_intervals = $TargetHeartbeatIntervals
    observed_heartbeat_intervals = $heartbeatDelta
    heartbeat_successes = $successDelta
    heartbeat_failures = $failureDelta
    samples = $samples
    ping_attempts_per_sample = $PingAttempts
    reset_count = $resetCount
    ping_failures = $pingFailures
    webui_failures = $webFailures
    health_failures = $healthFailures
    wifi_failures = $wifiFailures
    storage_failures = $storageFailures
    minimum_stack_margin_percent = if ($minimumStackMargin -eq 100 -and
        $null -eq $firstHealth) { $null } else { $minimumStackMargin }
    minimum_free_internal_heap_bytes = if (
        $minimumFreeInternal -eq [uint64]::MaxValue
    ) { $null } else { $minimumFreeInternal }
    minimum_largest_internal_block_bytes = if (
        $minimumLargestInternal -eq [uint64]::MaxValue
    ) { $null } else { $minimumLargestInternal }
    csv_path = $csvPath
    passed = $passed
}
$summary | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath $summaryPath -Encoding UTF8
$summary | ConvertTo-Json -Depth 4

if (-not $passed) {
    exit 1
}
