[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateCount(1, 2)]
    [string[]]$SensorUrls,
    [ValidateRange(1, 1440)]
    [int]$DurationMinutes = 30,
    [ValidateRange(5, 300)]
    [int]$IntervalSeconds = 5,
    [string]$OutputPath = (Join-Path $PWD ("sensor-monitor-{0}.jsonl" -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
)

$ErrorActionPreference = 'Stop'
$clients = foreach ($url in $SensorUrls) {
    [pscustomobject]@{
        Url = $url.TrimEnd('/')
        # New-Object lets Windows PowerShell load the WebRequestSession type
        # on demand; a static type literal can be resolved before the web
        # cmdlet assembly is loaded and fail on otherwise supported hosts.
        Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        Ready = $false
        NextSessionAttempt = [DateTimeOffset]::MinValue
        SessionError = $null
    }
}

function Open-LocalSession {
    param($Client)
    Invoke-RestMethod -Method Post -Uri "$($Client.Url)/api/v1/auth/session" `
        -Headers @{ Origin = $Client.Url } `
        -WebSession $Client.Session -ContentType 'application/json' -Body '{}' `
        -TimeoutSec 10 | Out-Null
    $Client.Ready = $true
}

$deadline = (Get-Date).AddMinutes($DurationMinutes)
while ((Get-Date) -lt $deadline) {
    foreach ($client in $clients) {
        $captured = [DateTimeOffset]::UtcNow.ToString('o')
        try {
            if (-not $client.Ready -and
                [DateTimeOffset]::UtcNow -ge $client.NextSessionAttempt) {
                try {
                    Open-LocalSession $client
                    $client.SessionError = $null
                }
                catch {
                    # Browser tabs may legitimately occupy all six protected
                    # sessions. Back off instead of turning a diagnostic soak
                    # into authentication traffic, and keep observing through
                    # the deliberately public, non-secret health endpoint.
                    $client.Ready = $false
                    $client.NextSessionAttempt = [DateTimeOffset]::UtcNow.AddSeconds(60)
                    $client.SessionError = $_.Exception.Message
                }
            }
            if ($client.Ready) {
                try {
                    $status = Invoke-RestMethod -Method Get `
                        -Uri "$($client.Url)/api/v1/ui/status" `
                        -WebSession $client.Session -TimeoutSec 10
                    [ordered]@{
                        captured_utc = $captured
                        source = 'sensor_status'
                        sensor_url = $client.Url
                        ok = $true
                        firmware = $status.device.firmware
                        uptime_seconds = $status.device.uptime_seconds
                        wifi = $status.health.wifi
                        server = $status.health.server
                        low_memory = $status.health.low_memory
                        rssi_dbm = $status.health.rssi_dbm
                        measured_at_utc_ms = $status.reading.measured_at_utc_ms
                        power_w = $status.reading.power_w
                        newest_sequence = $status.sync.newest_sequence
                        acknowledged_sequence = $status.sync.acknowledged_sequence
                        backlog = $status.sync.backlog
                    } | ConvertTo-Json -Compress | Add-Content -LiteralPath $OutputPath -Encoding utf8
                    continue
                }
                catch {
                    $client.Ready = $false
                    $client.NextSessionAttempt = [DateTimeOffset]::UtcNow.AddSeconds(60)
                    $client.SessionError = $_.Exception.Message
                }
            }

            $health = Invoke-RestMethod -Method Get `
                -Uri "$($client.Url)/api/local/health" -TimeoutSec 10
            [ordered]@{
                captured_utc = $captured
                source = 'sensor_health'
                sensor_url = $client.Url
                ok = $true
                session_degraded = $true
                session_error = $client.SessionError
                protocol = $health.protocol
                uptime_seconds = $health.uptime_seconds
                wifi_connected = $health.wifi_connected
                time_trusted = $health.time_trusted
                storage_writable = $health.storage_writable
                meter_healthy = $health.meter_healthy
                heartbeat_successes = $health.heartbeat_successes
                heartbeat_failures = $health.heartbeat_failures
                reading_batch_successes = $health.reading_batch_successes
                reading_batch_failures = $health.reading_batch_failures
                newest_sequence = $health.newest_stored_sequence
                acknowledged_sequence = $health.server_ack_sequence
                backlog = $health.durable_backlog_count
                free_internal_heap_bytes = $health.free_internal_heap_bytes
                largest_internal_block_bytes = $health.largest_internal_block_bytes
            } | ConvertTo-Json -Compress | Add-Content -LiteralPath $OutputPath -Encoding utf8
        }
        catch {
            $client.Ready = $false
            [ordered]@{
                captured_utc = $captured
                source = 'sensor_status'
                sensor_url = $client.Url
                ok = $false
                category = 'local_request_failed'
                detail = $_.Exception.Message
            } | ConvertTo-Json -Compress | Add-Content -LiteralPath $OutputPath -Encoding utf8
        }
    }
    Start-Sleep -Seconds $IntervalSeconds
}

Write-Host "Sensor timeline written to $OutputPath"
