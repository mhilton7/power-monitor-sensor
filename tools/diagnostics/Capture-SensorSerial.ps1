[CmdletBinding()]
param(
    [string]$Port = "",

    [ValidateRange(1, 3600)]
    [int]$DurationSeconds = 120,

    [ValidateRange(1200, 2000000)]
    [int]$BaudRate = 115200,

    [switch]$ResetDevice,

    [string]$LogDirectory = (Join-Path ([Environment]::GetFolderPath("UserProfile")) "PowerMonitorDiagnostics")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-CandidatePorts {
    $portNames = @([IO.Ports.SerialPort]::GetPortNames() | Sort-Object)
    if ($portNames.Count -eq 0) {
        return @()
    }

    $entities = @()
    try {
        $entities = @(Get-CimInstance Win32_PnPEntity -ErrorAction Stop |
            Where-Object { $_.Name -match "\(COM[0-9]+\)" })
    } catch {
        # Port names remain usable when CIM metadata is unavailable.
    }

    $results = @()
    foreach ($name in $portNames) {
        $entity = $entities |
            Where-Object { $_.Name -match "\($([regex]::Escape($name))\)" } |
            Select-Object -First 1
        $description = if ($entity) { [string]$entity.Name } else { "Serial port" }
        $deviceId = if ($entity) { [string]$entity.PNPDeviceID } else { "" }
        $likelyEsp32 = $description -match "USB JTAG|USB Serial|CP210|CH340|CH910|ESP32" -or
            $deviceId -match "VID_303A|VID_10C4|VID_1A86"
        $results += [PSCustomObject]@{
            Port = $name
            Description = $description
            LikelyEsp32 = $likelyEsp32
        }
    }
    return $results
}

function Protect-DiagnosticLine {
    param([string]$Line)

    if ($script:PrivateKeyBlock) {
        if ($Line -match "-----END [A-Z0-9 ]*PRIVATE KEY-----") {
            $script:PrivateKeyBlock = $false
        }
        return "[REDACTED PRIVATE KEY MATERIAL]"
    }
    if ($Line -match "-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----") {
        $script:PrivateKeyBlock = $true
        return "[REDACTED PRIVATE KEY MATERIAL]"
    }
    $protected = $Line
    $protected = [regex]::Replace(
        $protected,
        "(?i)(authorization|cookie|csrf|x-pm-signature|signature|device_secret|enrollment_secret|enrollment_token|token|wifi_password|admin_password|password)(\s*[:=]\s*).*$",
        '$1$2[REDACTED]'
    )
    return $protected
}

function Write-CaptureLine {
    param([string]$Message, [string]$Level = "SERIAL")

    $safe = Protect-DiagnosticLine -Line $Message
    $line = "[{0}][{1}] {2}" -f [DateTimeOffset]::Now.ToString("o"), $Level, $safe
    Write-Host $line
    Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8
}

$script:PrivateKeyBlock = $false
New-Item -ItemType Directory -Force -Path $LogDirectory | Out-Null
$resolvedDirectory = (Resolve-Path -LiteralPath $LogDirectory).Path
$script:LogPath = Join-Path $resolvedDirectory (
    "sensor-serial-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
)
$serial = $null

try {
    $candidates = @(Get-CandidatePorts)
    if ($Port) {
        $match = @($candidates | Where-Object {
            $_.Port -eq $Port.ToUpperInvariant()
        })
        if ($match.Count -eq 0) {
            throw "Port $Port is not present. Available ports: $($candidates.Port -join ', ')."
        }
        $selectedPort = $match[0].Port
        $description = $match[0].Description
    } else {
        $likely = @($candidates | Where-Object { $_.LikelyEsp32 })
        if ($likely.Count -eq 1) {
            $selectedPort = $likely[0].Port
            $description = $likely[0].Description
        } elseif ($candidates.Count -eq 1) {
            $selectedPort = $candidates[0].Port
            $description = $candidates[0].Description
        } elseif ($candidates.Count -eq 0) {
            throw "No serial ports were detected. Connect the ESP32-S3 and install its USB driver if needed."
        } else {
            $summary = ($candidates | ForEach-Object {
                "{0} ({1})" -f $_.Port, $_.Description
            }) -join "; "
            throw "More than one serial port is available. Rerun with -Port COMx. Detected: $summary"
        }
    }

    Write-CaptureLine ("Capture starting port={0} baud={1} duration_seconds={2} device={3}" -f
        $selectedPort, $BaudRate, $DurationSeconds, $description) "INFO"
    Write-CaptureLine "Sensitive key/value fields are redacted before console display and file storage." "INFO"

    $serial = [IO.Ports.SerialPort]::new(
        $selectedPort,
        $BaudRate,
        [IO.Ports.Parity]::None,
        8,
        [IO.Ports.StopBits]::One
    )
    $serial.Handshake = [IO.Ports.Handshake]::None
    $serial.ReadTimeout = 250
    $serial.DtrEnable = $false
    $serial.RtsEnable = $false
    $serial.NewLine = "`n"
    $serial.Open()

    if ($ResetDevice) {
        Write-CaptureLine "Requesting a normal USB serial hard reset." "INFO"
        # On an ESP32-S3 native USB-Serial/JTAG port, DTR controls GPIO0.
        # Asserting DTR and RTS together selects the ROM download boot path.
        # A normal application reset therefore pulses RTS (EN) only, matching
        # esptool's USB hard-reset sequence, while DTR remains deasserted.
        $serial.DtrEnable = $false
        $serial.RtsEnable = $true
        Start-Sleep -Milliseconds 200
        $serial.RtsEnable = $false
        Start-Sleep -Milliseconds 200
    }

    $deadline = [DateTime]::UtcNow.AddSeconds($DurationSeconds)
    $received = 0
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $line = $serial.ReadLine().TrimEnd("`r")
            Write-CaptureLine $line
            $received++
        } catch [TimeoutException] {
            # A short timeout keeps cancellation and the capture deadline responsive.
        }
    }

    if ($received -eq 0) {
        Write-CaptureLine "No serial lines were received. Check the port, close PuTTY/other monitors, and reset the board." "FAIL"
        exit 1
    }
    Write-CaptureLine ("Capture complete lines={0} log={1}" -f
        $received, $script:LogPath) "PASS"
    exit 0
} catch {
    Write-CaptureLine ("Capture failed: {0}" -f $_.Exception.Message) "FAIL"
    exit 1
} finally {
    if ($serial) {
        if ($serial.IsOpen) {
            $serial.Close()
        }
        $serial.Dispose()
    }
}
