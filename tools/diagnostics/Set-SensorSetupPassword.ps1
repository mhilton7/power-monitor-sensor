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
    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
        $byteLength = [Runtime.InteropServices.Marshal]::ReadInt32(
            $bstr,
            -4
        )
        $characters = [char[]]::new([int]($byteLength / 2))
        for ($index = 0; $index -lt $characters.Length; $index++) {
            $characters[$index] = [char][Runtime.InteropServices.Marshal]::ReadInt16(
                $bstr,
                $index * 2
            )
        }
        return ,$characters
    }
    finally {
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

$serial = $null
$password = $null
$confirmation = $null
$passwordCharacters = $null
$confirmationCharacters = $null
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

    $password = Read-Host (
        "Temporary setup-AP password (12-63 printable ASCII characters, " +
        "no spaces)"
    ) -AsSecureString
    $confirmation = Read-Host "Confirm temporary setup-AP password" -AsSecureString
    $passwordCharacters = ConvertTo-ClearedCharArray -Value $password
    $confirmationCharacters = ConvertTo-ClearedCharArray -Value $confirmation

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

    $prefix = [char[]]("setup-password {0} " -f $requestId)
    $commandCharacters = [char[]]::new(
        $prefix.Length + $passwordCharacters.Length + 2
    )
    [Array]::Copy($prefix, 0, $commandCharacters, 0, $prefix.Length)
    [Array]::Copy(
        $passwordCharacters,
        0,
        $commandCharacters,
        $prefix.Length,
        $passwordCharacters.Length
    )
    $commandCharacters[$commandCharacters.Length - 2] = [char]13
    $commandCharacters[$commandCharacters.Length - 1] = [char]10

    $serial.DiscardInBuffer()
    $serial.Write($commandCharacters, 0, $commandCharacters.Length)
    $serial.BaseStream.Flush()
    Clear-CharacterArray -Value $commandCharacters
    $commandCharacters = $null
    Clear-CharacterArray -Value $passwordCharacters
    $passwordCharacters = $null
    Clear-CharacterArray -Value $confirmationCharacters
    $confirmationCharacters = $null
    $password.Dispose()
    $password = $null
    $confirmation.Dispose()
    $confirmation = $null

    Write-Host "Password submitted. Waiting for verified device acknowledgment..."
    $successToken = "SETUP_AP_PASSWORD_APPLIED] request_id=$requestId"
    $rejectedToken = "SETUP_AP_PASSWORD_REJECTED] request_id=$requestId"
    $successIndex = 0
    $rejectedIndex = 0
    $applied = $false
    $rejected = $false
    $receiveBuffer = [char[]]::new(256)
    $deadline = [DateTime]::UtcNow.AddSeconds(30)

    while ([DateTime]::UtcNow -lt $deadline) {
        $received = 0
        try {
            $received = $serial.Read($receiveBuffer, 0, $receiveBuffer.Length)
        }
        catch [System.TimeoutException] {
            continue
        }

        try {
            for ($index = 0; $index -lt $received; $index++) {
                $successIndex = Update-TokenMatch `
                    -Character $receiveBuffer[$index] `
                    -Token $successToken `
                    -CurrentIndex $successIndex
                $rejectedIndex = Update-TokenMatch `
                    -Character $receiveBuffer[$index] `
                    -Token $rejectedToken `
                    -CurrentIndex $rejectedIndex
                if ($successIndex -eq $successToken.Length) {
                    $applied = $true
                    break
                }
                if ($rejectedIndex -eq $rejectedToken.Length) {
                    $rejected = $true
                    break
                }
            }
        }
        finally {
            if ($received -gt 0) {
                [Array]::Clear($receiveBuffer, 0, $received)
            }
        }
        if ($applied -or $rejected) {
            break
        }
    }

    if ($rejected) {
        throw "The device rejected or could not persist the setup-AP password."
    }
    if (-not $applied) {
        throw (
            "Timed out waiting for SETUP_AP_PASSWORD_APPLIED. Confirm the " +
            "firmware reported SETUP_AP_READY, then retry."
        )
    }

    Write-Host (
        "The device verified the password and requested an AP restart. Join " +
        "the non-secret SSID shown by SETUP_AP_READY using the password you entered."
    )
    $exitCode = 0
}
catch {
    [Console]::Error.WriteLine(
        ("ERROR: Setup-AP password was not applied: {0}" -f $_.Exception.Message)
    )
}
finally {
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
