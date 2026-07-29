[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CertificatePath,

    [string]$OutputDirectory = (Join-Path ([Environment]::GetFolderPath("UserProfile")) "PowerMonitorTLS")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$resolvedInput = (Resolve-Path -LiteralPath $CertificatePath).Path
$sourceText = Get-Content -LiteralPath $resolvedInput -Raw
if ($sourceText -match "-----BEGIN (?:RSA |EC )?PRIVATE KEY-----") {
    throw "The selected file contains a private key. Select Caddy's public root.crt; never copy root.key to a sensor."
}

$match = [regex]::Match(
    $sourceText,
    "-----BEGIN CERTIFICATE-----\s*(?<body>[A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----",
    [System.Text.RegularExpressions.RegexOptions]::Singleline
)
if (-not $match.Success) {
    throw "The selected file does not contain a PEM certificate."
}

$base64 = $match.Groups["body"].Value -replace "\s", ""
$der = [Convert]::FromBase64String($base64)
$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
try {
    $isCa = $false
    foreach ($extension in $certificate.Extensions) {
        if ($extension.Oid.Value -eq "2.5.29.19") {
            $constraints = [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new()
            $constraints.CopyFrom($extension)
            $isCa = $constraints.CertificateAuthority
        }
    }
    if (-not $isCa) {
        throw "The selected certificate is not marked as a CA certificate."
    }

    $formatted = [Convert]::ToBase64String(
        $der,
        [Base64FormattingOptions]::InsertLineBreaks
    )
    $pem = "-----BEGIN CERTIFICATE-----`r`n$formatted`r`n-----END CERTIFICATE-----`r`n"

    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    $resolvedOutput = (Resolve-Path -LiteralPath $OutputDirectory).Path
    $outputPath = Join-Path $resolvedOutput "power-monitor-server-ca.pem"
    Set-Content -LiteralPath $outputPath -Value $pem -Encoding ascii -NoNewline

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $fingerprint = ([BitConverter]::ToString($sha256.ComputeHash($der))).Replace("-", "")
    } finally {
        $sha256.Dispose()
    }

    Write-Host "Prepared public server CA certificate:"
    Write-Host "  $outputPath"
    Write-Host "Subject: $($certificate.Subject)"
    Write-Host "Issuer:  $($certificate.Issuer)"
    Write-Host "SHA-256: $fingerprint"
    Write-Host ""
    Write-Host "Paste the complete PEM file into 'Server CA certificate (public PEM)' during sensor setup."
    Write-Host "TrueNAS internal-CA source:"
    Write-Host "  /mnt/Apps/Power/power-monitor/caddy-data/caddy/pki/authorities/local/root.crt"
    Write-Host "Never copy or expose root.key."
} finally {
    $certificate.Dispose()
}
