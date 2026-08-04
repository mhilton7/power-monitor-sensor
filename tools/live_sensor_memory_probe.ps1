[CmdletBinding()]
param(
    [System.Collections.IDictionary]$Sensors = [ordered]@{
        "Outdoor-AC" = "192.168.0.202"
        "Indoor-AC"  = "192.168.0.26"
    },
    [ValidateRange(1, 3600)]
    [int]$IntervalSeconds = 10,
    [ValidateRange(0.1, 10080)]
    [double]$DurationMinutes = 20,
    [string]$OutputDirectory = "artifacts/live-memory-validation/pre-fix",
    [ValidateNotNullOrEmpty()]
    [string]$Phase = "pre-fix",
    [switch]$AllowHighFrequency
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Net.Http

if ($Sensors.Count -eq 0) {
    throw "At least one sensor is required."
}
if ($IntervalSeconds -lt 10 -and -not $AllowHighFrequency) {
    throw "Intervals below 10 seconds require -AllowHighFrequency after local-health is allocation-stable."
}

function Get-PathValue {
    param(
        [AllowNull()][object]$Document,
        [Parameter(Mandatory)][string[]]$Paths
    )
    foreach ($path in $Paths) {
        $cursor = $Document
        $found = $true
        foreach ($segment in $path.Split(".")) {
            if ($null -eq $cursor) {
                $found = $false
                break
            }
            $property = $cursor.PSObject.Properties[$segment]
            if ($null -eq $property) {
                $found = $false
                break
            }
            $cursor = $property.Value
        }
        if ($found) {
            return $cursor
        }
    }
    return $null
}

function Convert-ToNullableInt64 {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $null
    }
    $parsed = 0L
    if ([long]::TryParse([string]$Value, [ref]$parsed)) {
        return $parsed
    }
    return $null
}

function Get-LiveClassification {
    param(
        [AllowNull()][object]$SyncInProgress,
        [AllowNull()][object]$HighMemoryOwner,
        [AllowNull()][object]$FreeInternalHeapBytes,
        [AllowNull()][object]$LargestInternalBlockBytes
    )
    if ($SyncInProgress -eq $true) {
        return "TLS_ACTIVE_TRANSIENT"
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$HighMemoryOwner) -and
        [string]$HighMemoryOwner -ne "idle") {
        return "HIGH_MEMORY_OWNER_BUSY"
    }
    $free = Convert-ToNullableInt64 $FreeInternalHeapBytes
    $largest = Convert-ToNullableInt64 $LargestInternalBlockBytes
    if ($null -eq $free -or $null -eq $largest) {
        return "UNKNOWN"
    }
    if ($free -ge 65536 -and $largest -ge 32768) {
        return "HEALTHY_IDLE"
    }
    if ($free -ge 65536 -and $largest -lt 32768) {
        return "IDLE_FRAGMENTED"
    }
    if ($free -lt 65536) {
        return "IDLE_LOW_TOTAL"
    }
    return "UNKNOWN"
}

function Get-Median {
    param([object[]]$Values)
    $numbers = @($Values | ForEach-Object { Convert-ToNullableInt64 $_ } |
        Where-Object { $null -ne $_ } | Sort-Object)
    if ($numbers.Count -eq 0) {
        return $null
    }
    $middle = [math]::Floor($numbers.Count / 2)
    if (($numbers.Count % 2) -eq 1) {
        return $numbers[$middle]
    }
    return ($numbers[$middle - 1] + $numbers[$middle]) / 2.0
}

function Get-CounterDelta {
    param(
        [object[]]$Rows,
        [Parameter(Mandatory)][string]$Property
    )
    $values = @($Rows | ForEach-Object {
            Convert-ToNullableInt64 $_.$Property
        } | Where-Object { $null -ne $_ })
    if ($values.Count -lt 2) {
        return $null
    }
    $delta = $values[-1] - $values[0]
    if ($delta -lt 0) {
        return $null
    }
    return $delta
}

function Get-Maximum {
    param([object[]]$Values)
    $numbers = @($Values | ForEach-Object { Convert-ToNullableInt64 $_ } |
        Where-Object { $null -ne $_ })
    if ($numbers.Count -eq 0) {
        return $null
    }
    return ($numbers | Measure-Object -Maximum).Maximum
}

function Get-Minimum {
    param([object[]]$Values)
    $numbers = @($Values | ForEach-Object { Convert-ToNullableInt64 $_ } |
        Where-Object { $null -ne $_ })
    if ($numbers.Count -eq 0) {
        return $null
    }
    return ($numbers | Measure-Object -Minimum).Minimum
}

function Get-RecoverySeconds {
    param([object[]]$Rows)
    $recoveries = [System.Collections.Generic.List[double]]::new()
    $activeAt = $null
    foreach ($row in $Rows) {
        if ($row.Classification -eq "TLS_ACTIVE_TRANSIENT") {
            if ($null -eq $activeAt) {
                $activeAt = [datetimeoffset]::Parse($row.TimestampUtc)
            }
            continue
        }
        if ($null -ne $activeAt -and $row.Classification -eq "HEALTHY_IDLE") {
            $recoveredAt = [datetimeoffset]::Parse($row.TimestampUtc)
            $recoveries.Add(($recoveredAt - $activeAt).TotalSeconds)
            $activeAt = $null
        }
    }
    return $recoveries.ToArray()
}

$resolvedOutput = [System.IO.Path]::GetFullPath(
    (Join-Path (Get-Location) $OutputDirectory)
)
$rawDirectory = Join-Path $resolvedOutput "raw"
[System.IO.Directory]::CreateDirectory($rawDirectory) | Out-Null

$startedUtc = [datetimeoffset]::UtcNow
$deadlineUtc = $startedUtc.AddMinutes($DurationMinutes)
$rows = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()

$configuration = [ordered]@{
    schema_version = 1
    phase = $Phase
    sensors = [ordered]@{}
    interval_seconds = $IntervalSeconds
    duration_minutes = $DurationMinutes
    allow_high_frequency = [bool]$AllowHighFrequency
    request = "GET /api/local/health"
    mutating_requests = $false
    started_utc = $startedUtc.ToString("o")
    ended_utc = $null
}
foreach ($entry in $Sensors.GetEnumerator()) {
    $configuration.sensors[[string]$entry.Key] = [string]$entry.Value
}
$configuration | ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath (Join-Path $resolvedOutput "probe-configuration.json") -Encoding utf8

$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.UseProxy = $false
$client = [System.Net.Http.HttpClient]::new($handler)
$client.Timeout = [timespan]::FromSeconds([math]::Min(8, [math]::Max(2, $IntervalSeconds - 1)))
$iteration = 0
try {
    while ([datetimeoffset]::UtcNow -lt $deadlineUtc) {
        $cycleStarted = [datetimeoffset]::UtcNow
        foreach ($entry in $Sensors.GetEnumerator()) {
            $sensor = [string]$entry.Key
            $ip = [string]$entry.Value
            $timestampUtc = [datetimeoffset]::UtcNow
            $safeSensor = $sensor -replace "[^A-Za-z0-9_.-]", "_"
            $rawName = "{0:D6}-{1}-{2}.json" -f $iteration, $timestampUtc.ToString("yyyyMMddTHHmmssfffZ"), $safeSensor
            $rawPath = Join-Path $rawDirectory $rawName
            try {
                $url = "http://$ip/api/local/health"
                $response = $client.GetAsync($url).GetAwaiter().GetResult()
                $raw = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                if (-not $response.IsSuccessStatusCode) {
                    throw "HTTP $([int]$response.StatusCode)"
                }
                $raw | Set-Content -LiteralPath $rawPath -Encoding utf8
                $health = $raw | ConvertFrom-Json

                $syncInProgress = Get-PathValue $health @("sync_in_progress", "sync.in_progress")
                $highMemoryOwner = Get-PathValue $health @("high_memory_owner", "memory.high_memory_owner")
                $freeInternal = Get-PathValue $health @("free_internal_heap_bytes", "memory.free_internal_heap_bytes")
                $largestBlock = Get-PathValue $health @("largest_internal_block_bytes", "memory.largest_internal_block_bytes")
                $classification = Get-LiveClassification $syncInProgress $highMemoryOwner $freeInternal $largestBlock

                $row = [ordered]@{
                    TimestampUtc = $timestampUtc.ToString("o")
                    TimestampLocal = $timestampUtc.ToLocalTime().ToString("o")
                    Phase = $Phase
                    Sensor = $sensor
                    IP = $ip
                    UptimeSeconds = Get-PathValue $health @("uptime_seconds")
                    BootId = Get-PathValue $health @("boot_id", "identity.boot_id")
                    FirmwareVersion = Get-PathValue $health @("firmware_version", "identity.firmware_version")
                    FirmwareBuildHash = Get-PathValue $health @("firmware_build_hash", "build_hash", "git_commit", "identity.firmware_build_hash")
                    TimeTrusted = Get-PathValue $health @("time_trusted")
                    WiFiConnected = Get-PathValue $health @("wifi_connected")
                    RSSI = Get-PathValue $health @("rssi", "rssi_dbm", "network.rssi_dbm")
                    StorageWritable = Get-PathValue $health @("storage_writable")
                    StoragePresent = Get-PathValue $health @("storage_present")
                    StorageMounted = Get-PathValue $health @("storage_mounted")
                    StorageIndexHealthy = Get-PathValue $health @("storage_index_healthy")
                    StorageEventLogHealthy = Get-PathValue $health @("storage_event_log_healthy")
                    StorageEventLogIntegrityStatus = Get-PathValue $health @("storage_event_log_integrity_status")
                    MeterHealthy = Get-PathValue $health @("meter_healthy")
                    FreeTotalHeapBytes = Get-PathValue $health @("free_total_heap_bytes", "free_heap_bytes", "memory.free_total_heap_bytes")
                    FreeInternalHeapBytes = $freeInternal
                    LargestInternalBlockBytes = $largestBlock
                    MinimumFreeInternalHeapBytes = Get-PathValue $health @("minimum_free_internal_heap_bytes", "memory.minimum_free_internal_heap_bytes")
                    TlsTotalOk = Get-PathValue $health @("tls_total_ok", "tls_total_ready", "tls.total_ready")
                    TlsBlockOk = Get-PathValue $health @("tls_block_ok", "tls_block_ready", "tls.block_ready")
                    TlsReady = Get-PathValue $health @("tls_ready", "tls.ready")
                    TlsState = Get-PathValue $health @("tls_state", "tls.state")
                    SyncInProgress = $syncInProgress
                    SyncPending = Get-PathValue $health @("sync_pending")
                    PrimaryStoragePending = Get-PathValue $health @("primary_storage_pending")
                    DurableReadingBacklog = Get-PathValue $health @("durable_reading_backlog")
                    DurableBacklogCount = Get-PathValue $health @("durable_backlog_count")
                    HighMemoryOwner = $highMemoryOwner
                    MemoryOperationContext = Get-PathValue $health @("memory_operation_context", "memory.operation_context")
                    MemoryState = Get-PathValue $health @("memory_state", "memory.state")
                    MemorySeverity = Get-PathValue $health @("memory_severity", "memory.severity")
                    HeapIntegrityOk = Get-PathValue $health @("heap_integrity_ok", "memory.heap_integrity_ok")
                    HeartbeatSuccesses = Get-PathValue $health @("heartbeat_successes")
                    HeartbeatFailures = Get-PathValue $health @("heartbeat_failures")
                    HeartbeatTransportFailures = Get-PathValue $health @("heartbeat_transport_failures")
                    HeartbeatContractFailures = Get-PathValue $health @("heartbeat_contract_failures")
                    HeartbeatAuthenticationFailures = Get-PathValue $health @("heartbeat_authentication_failures")
                    LastHeartbeatUtcMs = Get-PathValue $health @("last_heartbeat_utc_ms")
                    LastHeartbeatAttemptMonotonicMs = Get-PathValue $health @("last_heartbeat_attempt_monotonic_ms")
                    LastHeartbeatSuccessMonotonicMs = Get-PathValue $health @("last_heartbeat_success_monotonic_ms")
                    HeartbeatSuccessAgeMs = if (
                        $null -ne (Convert-ToNullableInt64 (Get-PathValue $health @("uptime_seconds"))) -and
                        $null -ne (Convert-ToNullableInt64 (Get-PathValue $health @("last_heartbeat_success_monotonic_ms")))) {
                        [math]::Max(
                            0,
                            ((Convert-ToNullableInt64 (Get-PathValue $health @("uptime_seconds"))) * 1000) -
                            (Convert-ToNullableInt64 (Get-PathValue $health @("last_heartbeat_success_monotonic_ms")))
                        )
                    } else { $null }
                    TlsRequestsAdmitted = Get-PathValue $health @("tls_requests_admitted")
                    TlsRequestsRejectedHeap = Get-PathValue $health @("tls_requests_rejected_heap")
                    FragmentationDeferrals = Get-PathValue $health @("fragmentation_deferrals")
                    LocalResourceDeferrals = Get-PathValue $health @("local_resource_deferrals")
                    ReadingBatchSuccesses = Get-PathValue $health @("reading_batch_successes")
                    ReadingBatchFailures = Get-PathValue $health @("reading_batch_failures")
                    EventBatchSuccesses = Get-PathValue $health @("event_batch_successes")
                    EventBatchFailures = Get-PathValue $health @("event_batch_failures")
                    TransactionsStarted = Get-PathValue $health @("transactions_started")
                    TransactionsCompleted = Get-PathValue $health @("transactions_completed")
                    TransactionsFailed = Get-PathValue $health @("transactions_failed")
                    ServerAckSequence = Get-PathValue $health @("server_ack_sequence")
                    OldestStoredSequence = Get-PathValue $health @("oldest_stored_sequence")
                    OldestSyncableSequence = Get-PathValue $health @("oldest_syncable_sequence")
                    NewestStoredSequence = Get-PathValue $health @("newest_stored_sequence")
                    NewestSyncableSequence = Get-PathValue $health @("newest_syncable_sequence")
                    LastHeartbeatResult = Get-PathValue $health @("last_heartbeat_result")
                    LastLocalDeferralReason = Get-PathValue $health @("last_local_deferral_reason")
                    LastSyncError = Get-PathValue $health @("last_sync_error")
                    OtaState = Get-PathValue $health @("ota_state", "ota.state")
                    OtaReportPending = Get-PathValue $health @("ota_report_pending", "ota.report_pending")
                    StackHighWaterBytes = Get-PathValue $health @("stack_high_water_bytes")
                    StackMarginPercent = Get-PathValue $health @("stack_margin_percent")
                    StorageQueueDepth = Get-PathValue $health @("storage_queue_depth")
                    ActionQueueDepth = Get-PathValue $health @("action_queue_depth")
                    StorageDropped = Get-PathValue $health @("storage_dropped")
                    ActionDropped = Get-PathValue $health @("action_dropped")
                    RecordPoolCapacity = Get-PathValue $health @("record_pool_capacity")
                    RecordPoolActive = Get-PathValue $health @("record_pool_active")
                    RecordPoolPeak = Get-PathValue $health @("record_pool_peak")
                    RecordPoolExhaustions = Get-PathValue $health @("record_pool_exhaustions")
                    EventPoolCapacity = Get-PathValue $health @("event_pool_capacity")
                    EventPoolActive = Get-PathValue $health @("event_pool_active")
                    EventPoolPeak = Get-PathValue $health @("event_pool_peak")
                    EventPoolExhaustions = Get-PathValue $health @("event_pool_exhaustions")
                    Classification = $classification
                    HttpStatus = [int]$response.StatusCode
                    Error = ""
                }
                $rows.Add([pscustomobject]$row)
            }
            catch {
                $errorRecord = [ordered]@{
                    timestamp_utc = $timestampUtc.ToString("o")
                    phase = $Phase
                    sensor = $sensor
                    ip = $ip
                    error = $_.Exception.Message
                }
                $errors.Add([pscustomobject]$errorRecord)
                $errorRecord | ConvertTo-Json -Depth 4 |
                    Set-Content -LiteralPath ($rawPath + ".error.json") -Encoding utf8
            }
        }
        $iteration++
        $elapsed = ([datetimeoffset]::UtcNow - $cycleStarted).TotalMilliseconds
        $remaining = [math]::Max(0, ($IntervalSeconds * 1000) - $elapsed)
        $untilDeadline = ($deadlineUtc - [datetimeoffset]::UtcNow).TotalMilliseconds
        if ($untilDeadline -le 0) {
            break
        }
        $sleepMilliseconds = [math]::Min($remaining, $untilDeadline)
        if ($sleepMilliseconds -gt 0) {
            Start-Sleep -Milliseconds ([int]$sleepMilliseconds)
        }
    }
}
finally {
    $client.Dispose()
    $handler.Dispose()
}

$endedUtc = [datetimeoffset]::UtcNow
$csvPath = Join-Path $resolvedOutput "normalized.csv"
$rows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding utf8
$errors | ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath (Join-Path $resolvedOutput "errors.json") -Encoding utf8

$sensorSummaries = [ordered]@{}
foreach ($entry in $Sensors.GetEnumerator()) {
    $sensor = [string]$entry.Key
    $sensorRows = @($rows | Where-Object Sensor -eq $sensor)
    $idleRows = @($sensorRows | Where-Object {
            $_.Classification -in @("HEALTHY_IDLE", "IDLE_FRAGMENTED", "IDLE_LOW_TOTAL")
        })
    $activeRows = @($sensorRows | Where-Object Classification -eq "TLS_ACTIVE_TRANSIENT")
    $recoveries = @(Get-RecoverySeconds $sensorRows)
    $comparisonWindow = [math]::Max(1, [math]::Floor($idleRows.Count / 10))
    $initialIdleRows = @($idleRows | Select-Object -First $comparisonWindow)
    $finalIdleRows = @($idleRows | Select-Object -Last $comparisonWindow)
    $initialFreeMedian = Get-Median @($initialIdleRows | ForEach-Object { $_.FreeInternalHeapBytes })
    $finalFreeMedian = Get-Median @($finalIdleRows | ForEach-Object { $_.FreeInternalHeapBytes })
    $initialLargestMedian = Get-Median @($initialIdleRows | ForEach-Object { $_.LargestInternalBlockBytes })
    $finalLargestMedian = Get-Median @($finalIdleRows | ForEach-Object { $_.LargestInternalBlockBytes })
    $classCounts = [ordered]@{}
    foreach ($group in ($sensorRows | Group-Object Classification)) {
        $classCounts[$group.Name] = $group.Count
    }
    $sensorSummaries[$sensor] = [ordered]@{
        ip = [string]$entry.Value
        successful_samples = $sensorRows.Count
        failed_samples = @($errors | Where-Object sensor -eq $sensor).Count
        classifications = $classCounts
        idle_free_internal_median = Get-Median @($idleRows | ForEach-Object { $_.FreeInternalHeapBytes })
        idle_largest_block_median = Get-Median @($idleRows | ForEach-Object { $_.LargestInternalBlockBytes })
        initial_idle_free_internal_median = $initialFreeMedian
        final_idle_free_internal_median = $finalFreeMedian
        final_to_initial_free_internal_ratio = if ($initialFreeMedian -gt 0) { $finalFreeMedian / $initialFreeMedian } else { $null }
        initial_idle_largest_block_median = $initialLargestMedian
        final_idle_largest_block_median = $finalLargestMedian
        final_to_initial_largest_block_ratio = if ($initialLargestMedian -gt 0) { $finalLargestMedian / $initialLargestMedian } else { $null }
        minimum_idle_largest_block = if ($idleRows.Count) { ($idleRows | ForEach-Object { $_.LargestInternalBlockBytes } | Measure-Object -Minimum).Minimum } else { $null }
        active_tls_minimum_free_internal = if ($activeRows.Count) { ($activeRows | ForEach-Object { $_.FreeInternalHeapBytes } | Measure-Object -Minimum).Minimum } else { $null }
        active_tls_minimum_largest_block = if ($activeRows.Count) { ($activeRows | ForEach-Object { $_.LargestInternalBlockBytes } | Measure-Object -Minimum).Minimum } else { $null }
        post_tls_recovery_seconds = $recoveries
        heartbeat_increase = Get-CounterDelta $sensorRows "HeartbeatSuccesses"
        heartbeat_failure_increase = Get-CounterDelta $sensorRows "HeartbeatFailures"
        maximum_heartbeat_success_age_ms = Get-Maximum @($sensorRows | ForEach-Object { $_.HeartbeatSuccessAgeMs })
        reading_batch_increase = Get-CounterDelta $sensorRows "ReadingBatchSuccesses"
        reading_batch_failure_increase = Get-CounterDelta $sensorRows "ReadingBatchFailures"
        tls_heap_rejection_increase = Get-CounterDelta $sensorRows "TlsRequestsRejectedHeap"
        transaction_failure_increase = Get-CounterDelta $sensorRows "TransactionsFailed"
        storage_drop_increase = Get-CounterDelta $sensorRows "StorageDropped"
        action_drop_increase = Get-CounterDelta $sensorRows "ActionDropped"
        record_pool_exhaustion_increase = Get-CounterDelta $sensorRows "RecordPoolExhaustions"
        event_pool_exhaustion_increase = Get-CounterDelta $sensorRows "EventPoolExhaustions"
        maximum_storage_queue_depth = Get-Maximum @($sensorRows | ForEach-Object { $_.StorageQueueDepth })
        maximum_action_queue_depth = Get-Maximum @($sensorRows | ForEach-Object { $_.ActionQueueDepth })
        minimum_stack_high_water_bytes = Get-Minimum @($sensorRows | ForEach-Object { $_.StackHighWaterBytes })
        minimum_stack_margin_percent = Get-Minimum @($sensorRows | ForEach-Object { $_.StackMarginPercent })
        heap_integrity_failures = @($sensorRows | Where-Object HeapIntegrityOk -eq $false).Count
        storage_unmounted_samples = @($sensorRows | Where-Object StorageMounted -eq $false).Count
        storage_unwritable_samples = @($sensorRows | Where-Object StorageWritable -eq $false).Count
        meter_unhealthy_samples = @($sensorRows | Where-Object MeterHealthy -eq $false).Count
        event_log_unhealthy_samples = @($sensorRows | Where-Object StorageEventLogHealthy -eq $false).Count
        backlog_first = if ($sensorRows.Count) { $sensorRows[0].DurableBacklogCount } else { $null }
        backlog_last = if ($sensorRows.Count) { $sensorRows[-1].DurableBacklogCount } else { $null }
        boot_ids = @($sensorRows | ForEach-Object { $_.BootId } | Where-Object { $_ } | Sort-Object -Unique)
        firmware_versions = @($sensorRows | ForEach-Object { $_.FirmwareVersion } | Where-Object { $_ } | Sort-Object -Unique)
        firmware_build_hashes = @($sensorRows | ForEach-Object { $_.FirmwareBuildHash } | Where-Object { $_ } | Sort-Object -Unique)
    }
}

$summary = [ordered]@{
    schema_version = 1
    phase = $Phase
    started_utc = $startedUtc.ToString("o")
    ended_utc = $endedUtc.ToString("o")
    requested_duration_minutes = $DurationMinutes
    interval_seconds = $IntervalSeconds
    total_successful_samples = $rows.Count
    total_failed_samples = $errors.Count
    sensors = $sensorSummaries
}
$summary | ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath (Join-Path $resolvedOutput "summary.json") -Encoding utf8
$configuration.ended_utc = $endedUtc.ToString("o")
$configuration | ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath (Join-Path $resolvedOutput "probe-configuration.json") -Encoding utf8

Write-Output "Live sensor memory probe completed."
Write-Output "Phase: $Phase"
Write-Output "Samples: $($rows.Count) successful, $($errors.Count) failed"
Write-Output "Output: $resolvedOutput"
