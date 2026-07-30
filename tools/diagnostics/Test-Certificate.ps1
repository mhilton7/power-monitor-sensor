[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [Uri]$ServerUrl,

    [Parameter(Mandatory = $true)]
    [string]$CaCertificatePath,

    [string]$ConnectAddress = "",

    [string]$OpenSslPath = "",

    [string]$LogDirectory = (Join-Path ([Environment]::GetFolderPath("UserProfile")) "PowerMonitorDiagnostics")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-DiagnosticLog {
    param([string]$Directory)

    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    $resolved = (Resolve-Path -LiteralPath $Directory).Path
    return Join-Path $resolved ("power-monitor-certificate-{0}.log" -f
        (Get-Date -Format "yyyyMMdd-HHmmss"))
}

function Write-Diagnostic {
    param(
        [string]$Message,
        [ValidateSet("INFO", "PASS", "WARN", "FAIL")]
        [string]$Level = "INFO"
    )

    $line = "[{0}][{1}] {2}" -f [DateTimeOffset]::Now.ToString("o"), $Level, $Message
    Write-Host $line
    Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8
}

function Find-OpenSsl {
    param([string]$RequestedPath)

    if ($RequestedPath) {
        return (Resolve-Path -LiteralPath $RequestedPath).Path
    }
    foreach ($name in @("openssl.exe", "openssl")) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) {
            return $command.Source
        }
    }
    foreach ($candidate in @(
        "C:\Program Files\Git\mingw64\bin\openssl.exe",
        "C:\Program Files\Git\usr\bin\openssl.exe"
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    throw "OpenSSL was not found. Install Git for Windows/OpenSSL or pass -OpenSslPath."
}

function Invoke-OpenSsl {
    param([string[]]$Arguments)

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $lines = @("" | & $script:ResolvedOpenSsl @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    return [PSCustomObject]@{
        ExitCode = $exitCode
        Output = ($lines | ForEach-Object { [string]$_ }) -join "`n"
    }
}

function ConvertTo-Certificate {
    param([string]$Pem)

    $match = [regex]::Match(
        $Pem,
        "-----BEGIN CERTIFICATE-----\s*(?<body>[A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----",
        [Text.RegularExpressions.RegexOptions]::Singleline
    )
    if (-not $match.Success) {
        throw "No PEM certificate was found."
    }
    $der = [Convert]::FromBase64String(
        ($match.Groups["body"].Value -replace "\s", "")
    )
    return [Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
}

function Get-CertificateFingerprint {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $sha256.ComputeHash($Certificate.RawData)
        )).Replace("-", "")
    } finally {
        $sha256.Dispose()
    }
}

function Test-IsCertificateAuthority {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    foreach ($extension in $Certificate.Extensions) {
        if ($extension.Oid.Value -eq "2.5.29.19") {
            $constraints =
                [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new()
            $constraints.CopyFrom($extension)
            return $constraints.CertificateAuthority
        }
    }
    return $false
}

function Get-ConnectTarget {
    param([string]$HostName, [int]$Port, [string]$AddressOverride)

    $address = if ($AddressOverride) { $AddressOverride } else { $HostName }
    $parsed = $null
    if ([Net.IPAddress]::TryParse($address, [ref]$parsed) -and
        $parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
        return "[{0}]:{1}" -f $address, $Port
    }
    return "{0}:{1}" -f $address, $Port
}

$script:LogPath = New-DiagnosticLog -Directory $LogDirectory
$leafPath = ""
$caCertificate = $null
$leafCertificate = $null

try {
    Write-Diagnostic "Starting certificate validation. Log=$script:LogPath"
    if ($ServerUrl.Scheme -ne "https") {
        throw "ServerUrl must use HTTPS."
    }
    if ($ServerUrl.UserInfo -or $ServerUrl.Query -or $ServerUrl.Fragment) {
        throw "ServerUrl must not contain credentials, a query string, or a fragment."
    }

    $caPath = (Resolve-Path -LiteralPath $CaCertificatePath).Path
    $caText = Get-Content -LiteralPath $caPath -Raw
    if ($caText -match "-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----") {
        throw "The supplied file contains private-key material. Use only the public root.crt."
    }
    $caCertificate = ConvertTo-Certificate -Pem $caText
    if (-not (Test-IsCertificateAuthority -Certificate $caCertificate)) {
        throw "The supplied certificate is not marked as a certificate authority."
    }
    $now = Get-Date
    if ($now -lt $caCertificate.NotBefore -or $now -gt $caCertificate.NotAfter) {
        throw "The CA certificate is outside its validity period."
    }
    Write-Diagnostic ("CA subject={0}" -f $caCertificate.Subject) "INFO"
    Write-Diagnostic ("CA issuer={0}" -f $caCertificate.Issuer) "INFO"
    Write-Diagnostic ("CA validity_utc={0:o}..{1:o}" -f
        $caCertificate.NotBefore.ToUniversalTime(),
        $caCertificate.NotAfter.ToUniversalTime()) "PASS"
    Write-Diagnostic ("CA sha256={0}" -f
        (Get-CertificateFingerprint -Certificate $caCertificate)) "INFO"

    $script:ResolvedOpenSsl = Find-OpenSsl -RequestedPath $OpenSslPath
    $hostName = $ServerUrl.DnsSafeHost
    $port = $ServerUrl.Port
    $parsedIp = $null
    $hostIsIp = [Net.IPAddress]::TryParse($hostName, [ref]$parsedIp)
    $connectTarget = Get-ConnectTarget -HostName $hostName -Port $port `
        -AddressOverride $ConnectAddress
    $verifyOption = if ($hostIsIp) { "-verify_ip" } else { "-verify_hostname" }
    $tlsArguments = @(
        "s_client",
        "-showcerts",
        "-connect", $connectTarget
    )
    if (-not $hostIsIp) {
        $tlsArguments += @("-servername", $hostName)
    }
    $tlsArguments += @(
        "-CAfile", $caPath,
        "-verify_return_error",
        $verifyOption, $hostName
    )
    $result = Invoke-OpenSsl -Arguments $tlsArguments
    $verified = $result.Output -match "Verify return code:\s*0\s*\(ok\)"
    if (-not $verified) {
        throw ("TLS chain or {0} verification failed (OpenSSL exit {1})." -f
            $(if ($hostIsIp) { "IP SAN" } else { "hostname/SAN" }),
            $result.ExitCode)
    }

    $leafMatch = [regex]::Match(
        $result.Output,
        "-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----"
    )
    if (-not $leafMatch.Success) {
        throw "The server did not present a parseable leaf certificate."
    }
    $leafCertificate = ConvertTo-Certificate -Pem $leafMatch.Value
    if ($now -lt $leafCertificate.NotBefore -or $now -gt $leafCertificate.NotAfter) {
        throw "The server leaf certificate is outside its validity period."
    }
    Write-Diagnostic ("Leaf subject={0}" -f $leafCertificate.Subject) "INFO"
    Write-Diagnostic ("Leaf issuer={0}" -f $leafCertificate.Issuer) "INFO"
    Write-Diagnostic ("Leaf validity_utc={0:o}..{1:o}" -f
        $leafCertificate.NotBefore.ToUniversalTime(),
        $leafCertificate.NotAfter.ToUniversalTime()) "PASS"
    Write-Diagnostic ("Leaf sha256={0}" -f
        (Get-CertificateFingerprint -Certificate $leafCertificate)) "INFO"

    $leafPath = [IO.Path]::GetTempFileName()
    [IO.File]::WriteAllText($leafPath, $leafMatch.Value + "`r`n",
        [Text.Encoding]::ASCII)
    $details = Invoke-OpenSsl -Arguments @(
        "x509", "-in", $leafPath, "-noout", "-ext", "subjectAltName"
    )
    if ($details.ExitCode -ne 0) {
        throw "OpenSSL could not inspect the leaf subjectAltName extension."
    }
    foreach ($line in @($details.Output -split "`r?`n" |
        Where-Object { $_.Trim() })) {
        Write-Diagnostic ("Leaf {0}" -f $line.Trim())
    }

    Write-Diagnostic ("Verified TLS trust and {0} identity={1}; sni={2}; proxy bypassed." -f
        $(if ($hostIsIp) { "IP SAN" } else { "DNS SAN" }),
        $hostName,
        $(if ($hostIsIp) { "not-applicable-to-ip-literal" } else { $hostName })) "PASS"
    exit 0
} catch {
    Write-Diagnostic ("Certificate validation failed: {0}" -f $_.Exception.Message) "FAIL"
    exit 1
} finally {
    if ($caCertificate) {
        $caCertificate.Dispose()
    }
    if ($leafCertificate) {
        $leafCertificate.Dispose()
    }
    if ($leafPath -and (Test-Path -LiteralPath $leafPath)) {
        Remove-Item -LiteralPath $leafPath -Force
    }
}
