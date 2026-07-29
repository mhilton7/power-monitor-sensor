[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [Uri]$ServerUrl,

    [string]$OutputDirectory = (Join-Path ([Environment]::GetFolderPath("UserProfile")) "PowerMonitorTLS\downloaded"),

    [string]$ExpectedLeafSha256 = "",

    [string]$OpenSslPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($ServerUrl.Scheme -ne "https") {
    throw "ServerUrl must use https."
}

if (-not $OpenSslPath) {
    $command = Get-Command openssl -ErrorAction SilentlyContinue
    if ($command) {
        $OpenSslPath = $command.Source
    } else {
        $candidates = @(
            "C:\Program Files\Git\usr\bin\openssl.exe",
            "C:\Program Files\Git\mingw64\bin\openssl.exe"
        )
        $OpenSslPath = $candidates |
            Where-Object { Test-Path -LiteralPath $_ } |
            Select-Object -First 1
    }
}

if (-not $OpenSslPath -or -not (Test-Path -LiteralPath $OpenSslPath)) {
    throw "OpenSSL was not found. Install OpenSSL or Git for Windows, or provide -OpenSslPath."
}

$serverHost = $ServerUrl.DnsSafeHost
$serverPort = $ServerUrl.Port
$connectHost = if ($serverHost.Contains(":")) { "[$serverHost]" } else { $serverHost }
$connectTarget = "${connectHost}:$serverPort"

Write-Host "Connecting to $connectTarget and requesting the presented TLS chain..."
$previousErrorActionPreference = $ErrorActionPreference
try {
    $ErrorActionPreference = "SilentlyContinue"
    $rawOutput = "" |
        & $OpenSslPath s_client -showcerts -connect $connectTarget -servername $serverHost 2>$null |
        Out-String
} finally {
    $ErrorActionPreference = $previousErrorActionPreference
}

$matches = [regex]::Matches(
    $rawOutput,
    "-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    [System.Text.RegularExpressions.RegexOptions]::Singleline
)
if ($matches.Count -eq 0) {
    throw "The server did not present a parseable certificate chain."
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$resolvedOutput = (Resolve-Path -LiteralPath $OutputDirectory).Path

function ConvertTo-NormalizedPem {
    param([string]$Pem)

    $body = $Pem `
        -replace "-----BEGIN CERTIFICATE-----", "" `
        -replace "-----END CERTIFICATE-----", "" `
        -replace "\s", ""
    $der = [Convert]::FromBase64String($body)
    $formatted = [Convert]::ToBase64String(
        $der,
        [Base64FormattingOptions]::InsertLineBreaks
    )
    return [PSCustomObject]@{
        Der = $der
        Pem = "-----BEGIN CERTIFICATE-----`r`n$formatted`r`n-----END CERTIFICATE-----`r`n"
    }
}

function Get-Sha256Hex {
    param([byte[]]$Data)

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($Data))).Replace("-", "")
    } finally {
        $sha256.Dispose()
    }
}

$certificates = @()
for ($index = 0; $index -lt $matches.Count; $index++) {
    $normalized = ConvertTo-NormalizedPem -Pem $matches[$index].Value
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $normalized.Der
    )
    $isCa = $false
    foreach ($extension in $certificate.Extensions) {
        if ($extension.Oid.Value -eq "2.5.29.19") {
            $constraints = [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new()
            $constraints.CopyFrom($extension)
            $isCa = $constraints.CertificateAuthority
        }
    }
    $certificates += [PSCustomObject]@{
        Index = $index
        Certificate = $certificate
        Pem = $normalized.Pem
        IsCa = $isCa
        Sha256 = Get-Sha256Hex -Data $normalized.Der
    }
}

$leaf = $certificates[0]
$expected = ($ExpectedLeafSha256 -replace "[^0-9A-Fa-f]", "").ToUpperInvariant()
if ($expected -and $expected -ne $leaf.Sha256) {
    throw "Leaf certificate SHA-256 mismatch. Expected $expected but received $($leaf.Sha256)."
}

foreach ($item in $certificates) {
    $role = if ($item.Index -eq 0) { "leaf" } elseif ($item.IsCa) { "ca" } else { "chain" }
    $path = Join-Path $resolvedOutput ("certificate-{0}-{1}.pem" -f $item.Index, $role)
    Set-Content -LiteralPath $path -Value $item.Pem -Encoding ascii -NoNewline
    Write-Host ("[{0}] {1}" -f $item.Index, $item.Certificate.Subject)
    Write-Host "    Issuer: $($item.Certificate.Issuer)"
    Write-Host "    SHA-256: $($item.Sha256)"
    Write-Host "    Saved: $path"
}

$fingerprintPath = Join-Path $resolvedOutput "leaf-sha256.txt"
Set-Content -LiteralPath $fingerprintPath -Value $leaf.Sha256 -Encoding ascii

$caCandidate = $certificates |
    Where-Object { $_.Index -gt 0 -and $_.IsCa } |
    Select-Object -Last 1
if ($caCandidate) {
    $caPath = Join-Path $resolvedOutput "ca-candidate.pem"
    Set-Content -LiteralPath $caPath -Value $caCandidate.Pem -Encoding ascii -NoNewline
    Write-Host ""
    Write-Host "CA candidate: $caPath"
    Write-Host "Paste that PEM into the sensor only after independently verifying its SHA-256 value."
} else {
    Write-Warning "The server did not present a CA certificate. This is common because TLS servers normally omit the root CA."
    Write-Host "Use the displayed leaf SHA-256 in the sensor fingerprint field, or obtain the CA from the server administrator."
}

if ($expected) {
    Write-Host "The leaf certificate matched the independently supplied SHA-256 fingerprint."
} else {
    Write-Warning "This capture was not authenticated. Pulling a certificate from an untrusted connection does not establish trust and is vulnerable to interception."
}

foreach ($item in $certificates) {
    $item.Certificate.Dispose()
}
