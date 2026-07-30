#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^(?i:COM)[1-9][0-9]*$')]
    [string]$Port
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function ConvertTo-ClearedCharArray {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$Value
    )

    $bstr = [IntPtr]::Zero
    $characters = $null
    $conversionCompleted = $false
    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
        $byteLength = [Runtime.InteropServices.Marshal]::ReadInt32($bstr, -4)
        $characters = [char[]]::new([int]($byteLength / 2))
        for ($index = 0; $index -lt $characters.Length; $index++) {
            $characters[$index] = [char][Runtime.InteropServices.Marshal]::ReadInt16(
                $bstr,
                $index * 2
            )
        }
        $conversionCompleted = $true
        return ,$characters
    }
    finally {
        if (
            -not $conversionCompleted -and
            $null -ne $characters -and
            $characters.Length -gt 0
        ) {
            [Array]::Clear($characters, 0, $characters.Length)
        }
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function Clear-CharacterArray {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [char[]]$Value
    )

    if ($null -ne $Value -and $Value.Length -gt 0) {
        [Array]::Clear($Value, 0, $Value.Length)
    }
}

function Update-TokenMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [char]$Character,

        [Parameter(Mandatory = $true)]
        [string]$Token,

        [Parameter(Mandatory = $true)]
        [int]$CurrentIndex
    )

    if ($Character -eq $Token[$CurrentIndex]) {
        return $CurrentIndex + 1
    }
    if ($Character -eq $Token[0]) {
        return 1
    }
    return 0
}

function Wait-ForAdminRecoveryReady {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Ports.SerialPort]$Serial,

        [Parameter(Mandatory = $true)]
        [char[]]$BeginCommandCharacters,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ReadyToken,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory = $true)]
        [char[]]$Buffer
    )

    $readyIndex = 0
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $nextBeginAttempt = [DateTime]::MinValue

    while ([DateTime]::UtcNow -lt $deadline) {
        if ([DateTime]::UtcNow -ge $nextBeginAttempt) {
            try {
                $Serial.Write(
                    $BeginCommandCharacters,
                    0,
                    $BeginCommandCharacters.Length
                )
                $Serial.BaseStream.Flush()
            }
            catch [System.TimeoutException] {
                # Native USB may still be re-enumerating after the port opens.
            }
            catch [System.IO.IOException] {
                # Keep retrying the same non-secret request during the boot window.
            }
            $nextBeginAttempt = [DateTime]::UtcNow.AddSeconds(2)
        }

        $received = 0
        try {
            $received = $Serial.Read($Buffer, 0, $Buffer.Length)
        }
        catch [System.TimeoutException] {
            continue
        }
        catch [System.IO.IOException] {
            continue
        }

        try {
            for ($index = 0; $index -lt $received; $index++) {
                $readyIndex = Update-TokenMatch `
                    -Character $Buffer[$index] `
                    -Token $ReadyToken `
                    -CurrentIndex $readyIndex
                if ($readyIndex -eq $ReadyToken.Length) {
                    return $true
                }
            }
        }
        finally {
            if ($received -gt 0) {
                [Array]::Clear($Buffer, 0, $received)
            }
        }
    }

    return $false
}

function Wait-ForSerialToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Ports.SerialPort]$Serial,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Tokens,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory = $true)]
        [char[]]$Buffer
    )

    $matchIndexes = [int[]]::new($Tokens.Length)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)

    while ([DateTime]::UtcNow -lt $deadline) {
        $received = 0
        try {
            $received = $Serial.Read($Buffer, 0, $Buffer.Length)
        }
        catch [System.TimeoutException] {
            continue
        }

        try {
            for ($index = 0; $index -lt $received; $index++) {
                for ($tokenIndex = 0; $tokenIndex -lt $Tokens.Length; $tokenIndex++) {
                    $matchIndexes[$tokenIndex] = Update-TokenMatch `
                        -Character $Buffer[$index] `
                        -Token $Tokens[$tokenIndex] `
                        -CurrentIndex $matchIndexes[$tokenIndex]
                    if ($matchIndexes[$tokenIndex] -eq $Tokens[$tokenIndex].Length) {
                        return $tokenIndex
                    }
                }
            }
        }
        finally {
            if ($received -gt 0) {
                [Array]::Clear($Buffer, 0, $received)
            }
        }
    }

    return -1
}

$serial = $null
$password = $null
$confirmation = $null
$passwordCharacters = $null
$confirmationCharacters = $null
$beginCommandCharacters = $null
$commandPrefixCharacters = $null
$commandCharacters = $null
$receiveBuffer = $null
$requestIdBytes = $null
$randomNumberGenerator = $null
$exitCode = 1

try {
    $normalizedPort = $Port.ToUpperInvariant()
    Write-Host (
        (
            "Opening {0} at 115200 baud. Close PuTTY, PlatformIO Monitor, and " +
            "other programs that may own the port."
        ) -f $normalizedPort
    )
    Write-Host (
        "This helper works only with the temporary esp32-s3-admin-recovery " +
        "firmware. It preserves Wi-Fi, server, TLS, and enrollment settings."
    )

    $serial = [System.IO.Ports.SerialPort]::new(
        $normalizedPort,
        115200,
        [System.IO.Ports.Parity]::None,
        8,
        [System.IO.Ports.StopBits]::One
    )
    $serial.Handshake = [System.IO.Ports.Handshake]::None
    $serial.DtrEnable = $false
    $serial.RtsEnable = $false
    $serial.ReadTimeout = 500
    $serial.WriteTimeout = 5000
    $serial.Encoding = [Text.Encoding]::ASCII
    $serial.Open()
    $serial.DiscardInBuffer()
    $serial.DiscardOutBuffer()

    $requestIdBytes = [byte[]]::new(8)
    $randomNumberGenerator =
        [Security.Cryptography.RandomNumberGenerator]::Create()
    $randomNumberGenerator.GetBytes($requestIdBytes)
    $requestId = (
        ($requestIdBytes | ForEach-Object { $_.ToString('x2') }) -join ''
    )
    $randomNumberGenerator.Dispose()
    $randomNumberGenerator = $null

    $beginCommandCharacters = [char[]](
        "admin-recovery-begin {0}`r`n" -f $requestId
    )
    $readyToken = (
        "[ADMIN_PASSWORD_RECOVERY_READY] request_id={0} " +
        "window_ms=180000 transport=physical_usb secret_requested=false`r`n"
    ) -f $requestId
    $receiveBuffer = [char[]]::new(256)
    $readyTimeoutSeconds = 45

    Write-Host (
        "Waiting for the temporary recovery firmware to boot and confirm " +
        "the physical recovery request..."
    )
    $ready = Wait-ForAdminRecoveryReady `
        -Serial $serial `
        -BeginCommandCharacters $beginCommandCharacters `
        -ReadyToken $readyToken `
        -TimeoutSeconds $readyTimeoutSeconds `
        -Buffer $receiveBuffer
    Clear-CharacterArray -Value $beginCommandCharacters
    $beginCommandCharacters = $null
    if (-not $ready) {
        throw (
            "Timed out waiting for an exact matching " +
            "ADMIN_PASSWORD_RECOVERY_READY response. Confirm that the " +
            "temporary recovery firmware is running, then retry."
        )
    }

    $serial.DiscardInBuffer()
    Write-Host (
        "The temporary recovery firmware confirmed the request. Enter the " +
        "new password within its three-minute physical recovery window."
    )
    $password = Read-Host (
        "New administrator password (12-63 printable ASCII characters, " +
        "no spaces)"
    ) -AsSecureString
    $confirmation = Read-Host "Confirm new administrator password" -AsSecureString
    $passwordCharacters = ConvertTo-ClearedCharArray -Value $password
    $confirmationCharacters = ConvertTo-ClearedCharArray -Value $confirmation
    $password.Dispose()
    $password = $null
    $confirmation.Dispose()
    $confirmation = $null

    if (
        $passwordCharacters.Length -lt 12 -or
        $passwordCharacters.Length -gt 63
    ) {
        throw "Password length must be 12 through 63 characters."
    }

    $validCharacters = $true
    foreach ($character in $passwordCharacters) {
        $codePoint = [int]$character
        if ($codePoint -lt 0x21 -or $codePoint -gt 0x7E) {
            $validCharacters = $false
        }
    }
    if (-not $validCharacters) {
        throw "Password must contain only printable ASCII characters without whitespace."
    }

    $different = $passwordCharacters.Length -ne $confirmationCharacters.Length
    $maximumLength = [Math]::Max(
        $passwordCharacters.Length,
        $confirmationCharacters.Length
    )
    for ($index = 0; $index -lt $maximumLength; $index++) {
        $left = if ($index -lt $passwordCharacters.Length) {
            [int]$passwordCharacters[$index]
        }
        else {
            0
        }
        $right = if ($index -lt $confirmationCharacters.Length) {
            [int]$confirmationCharacters[$index]
        }
        else {
            0
        }
        $different = $different -or (($left -bxor $right) -ne 0)
    }
    if ($different) {
        throw "Password confirmation did not match."
    }
    Clear-CharacterArray -Value $confirmationCharacters
    $confirmationCharacters = $null

    $commandPrefixCharacters = [char[]](
        "admin-password {0} " -f $requestId
    )
    $commandCharacters = [char[]]::new(
        $commandPrefixCharacters.Length + $passwordCharacters.Length + 2
    )
    [Array]::Copy(
        $commandPrefixCharacters,
        0,
        $commandCharacters,
        0,
        $commandPrefixCharacters.Length
    )
    [Array]::Copy(
        $passwordCharacters,
        0,
        $commandCharacters,
        $commandPrefixCharacters.Length,
        $passwordCharacters.Length
    )
    $commandCharacters[$commandCharacters.Length - 2] = [char]13
    $commandCharacters[$commandCharacters.Length - 1] = [char]10
    Clear-CharacterArray -Value $commandPrefixCharacters
    $commandPrefixCharacters = $null

    $serial.DiscardInBuffer()
    $serial.Write($commandCharacters, 0, $commandCharacters.Length)
    $serial.BaseStream.Flush()
    Clear-CharacterArray -Value $commandCharacters
    $commandCharacters = $null
    Clear-CharacterArray -Value $passwordCharacters
    $passwordCharacters = $null

    Write-Host (
        "Password submitted. Waiting for the fixed, request-bound device " +
        "result..."
    )
    $successToken = (
        "[ADMIN_PASSWORD_RECOVERY_APPLIED] request_id={0} persisted=true " +
        "readback_verified=true configuration_preserved=true " +
        "production_restore_required=true secret_logged=false`r`n"
    ) -f $requestId
    $rejectedPreservedToken = (
        "[ADMIN_PASSWORD_RECOVERY_REJECTED] request_id={0} persisted=false " +
        "configuration_preserved=true secret_logged=false " +
        "requirement=12_to_63_printable_non_whitespace`r`n"
    ) -f $requestId
    $rejectedUnverifiedToken = (
        "[ADMIN_PASSWORD_RECOVERY_REJECTED] request_id={0} persisted=false " +
        "configuration_preserved=unverified secret_logged=false " +
        "requirement=12_to_63_printable_non_whitespace`r`n"
    ) -f $requestId
    $resultTimeoutSeconds = 120
    $resultIndex = Wait-ForSerialToken `
        -Serial $serial `
        -Tokens @(
            $successToken,
            $rejectedPreservedToken,
            $rejectedUnverifiedToken
        ) `
        -TimeoutSeconds $resultTimeoutSeconds `
        -Buffer $receiveBuffer

    if ($resultIndex -eq 1 -or $resultIndex -eq 2) {
        throw "The device rejected or rolled back the administrator password."
    }
    if ($resultIndex -ne 0) {
        throw (
            "Timed out waiting for an exact matching fixed recovery result. " +
            "The password outcome is unknown; keep the device offline and " +
            "retry recovery before restoring production firmware."
        )
    }

    Write-Host (
        "The device saved and read-back verified the new administrator " +
        "password. The temporary recovery firmware stays offline and cannot " +
        "return the sensor to service. You must reflash " +
        "esp32-s3-release without erasing configuration."
    )
    $exitCode = 0
}
catch {
    [Console]::Error.WriteLine(
        (
            "ERROR: Administrator password recovery failed or was not " +
            "verified: {0}"
        ) -f $_.Exception.Message
    )
}
finally {
    Clear-CharacterArray -Value $beginCommandCharacters
    Clear-CharacterArray -Value $commandPrefixCharacters
    Clear-CharacterArray -Value $commandCharacters
    Clear-CharacterArray -Value $passwordCharacters
    Clear-CharacterArray -Value $confirmationCharacters
    Clear-CharacterArray -Value $receiveBuffer
    if ($null -ne $requestIdBytes) {
        [Array]::Clear($requestIdBytes, 0, $requestIdBytes.Length)
    }
    if ($null -ne $randomNumberGenerator) {
        $randomNumberGenerator.Dispose()
    }
    if ($null -ne $password) {
        $password.Dispose()
    }
    if ($null -ne $confirmation) {
        $confirmation.Dispose()
    }
    if ($null -ne $serial) {
        if ($serial.IsOpen) {
            $serial.Close()
        }
        $serial.Dispose()
    }
}

exit $exitCode
