[CmdletBinding()]
param(
    [Uri]$ServerUrl = "https://power-monitor.local:8443",

    [Parameter(Mandatory = $true)]
    [string]$CaCertificatePath,

    [string]$ConnectAddress = "",

    [string]$OpenSslPath = "",

    [string]$LogDirectory = (Join-Path ([Environment]::GetFolderPath("UserProfile")) "PowerMonitorDiagnostics")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-DiagnosticLog {
    param([string]$Directory, [string]$Prefix)

    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    $resolved = (Resolve-Path -LiteralPath $Directory).Path
    return Join-Path $resolved ("{0}-{1}.log" -f $Prefix, (Get-Date -Format "yyyyMMdd-HHmmss"))
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
    $command = Get-Command openssl.exe -ErrorAction SilentlyContinue
    if (-not $command) {
        $command = Get-Command openssl -ErrorAction SilentlyContinue
    }
    if ($command) {
        return $command.Source
    }
    $candidates = @(
        "C:\Program Files\Git\mingw64\bin\openssl.exe",
        "C:\Program Files\Git\usr\bin\openssl.exe"
    )
    $candidate = $candidates |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
    if ($candidate) {
        return $candidate
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

function Test-PublicCaFile {
    param([string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $text = Get-Content -LiteralPath $resolved -Raw
    if ($text -match "-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----") {
        throw "The CA file contains a private key. Use only the public root.crt certificate."
    }
    $match = [regex]::Match(
        $text,
        "-----BEGIN CERTIFICATE-----\s*(?<body>[A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----",
        [Text.RegularExpressions.RegexOptions]::Singleline
    )
    if (-not $match.Success) {
        throw "The CA file does not contain a PEM certificate."
    }
    $der = [Convert]::FromBase64String(
        ($match.Groups["body"].Value -replace "\s", "")
    )
    $certificate =
        [Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
    try {
        $isCa = $false
        foreach ($extension in $certificate.Extensions) {
            if ($extension.Oid.Value -eq "2.5.29.19") {
                $constraints =
                    [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new()
                $constraints.CopyFrom($extension)
                $isCa = $constraints.CertificateAuthority
            }
        }
        if (-not $isCa) {
            throw "The supplied certificate is not marked as a certificate authority."
        }
        $now = Get-Date
        if ($now -lt $certificate.NotBefore -or $now -gt $certificate.NotAfter) {
            throw "The supplied CA certificate is outside its validity period."
        }
    } finally {
        $certificate.Dispose()
    }
    return $resolved
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

$script:LogPath = New-DiagnosticLog -Directory $LogDirectory -Prefix "power-monitor-server"
$failures = New-Object System.Collections.Generic.List[string]

try {
    Write-Diagnostic "Starting Power Monitor server diagnostics. Log=$script:LogPath"

    if ($ServerUrl.Scheme -ne "https") {
        throw "ServerUrl must use HTTPS."
    }
    if ($ServerUrl.UserInfo -or $ServerUrl.Query -or $ServerUrl.Fragment) {
        throw "ServerUrl must not contain credentials, a query string, or a fragment."
    }

    $caPath = Test-PublicCaFile -Path $CaCertificatePath
    $script:ResolvedOpenSsl = Find-OpenSsl -RequestedPath $OpenSslPath
    $serverHost = $ServerUrl.DnsSafeHost
    $serverPort = $ServerUrl.Port
    $parsedServerIp = $null
    $hostIsIp = [Net.IPAddress]::TryParse($serverHost, [ref]$parsedServerIp)
    Write-Diagnostic ("Target origin={0} identity_type={1} proxy=disabled" -f
        $ServerUrl.GetLeftPart([UriPartial]::Authority),
        $(if ($hostIsIp) { "ip-san" } else { "dns-san" }))
    Write-Diagnostic "Public CA file parsed; private-key material was not present." "PASS"

    if ($hostIsIp) {
        Write-Diagnostic "The URL uses an IP literal; DNS lookup is not applicable." "PASS"
    } else {
        try {
            $answers = @(Resolve-DnsName -Name $serverHost -ErrorAction Stop |
                Where-Object { $_.IPAddress } |
                Select-Object -ExpandProperty IPAddress -Unique)
            if ($answers.Count -eq 0) {
                throw "No A or AAAA address was returned."
            }
            Write-Diagnostic ("DNS resolved host={0} addresses={1}" -f
                $serverHost, ($answers -join ",")) "PASS"
        } catch {
            $failures.Add("DNS resolution failed for $serverHost.")
            Write-Diagnostic ("DNS resolution failed host={0} reason={1}" -f
                $serverHost, $_.Exception.Message) "FAIL"
        }
    }
    try {
        $pingSucceeded = [bool](Test-Connection -ComputerName $serverHost `
            -Count 1 -Quiet -ErrorAction Stop)
        if ($pingSucceeded) {
            Write-Diagnostic ("ICMP echo succeeded host={0}" -f $serverHost) "PASS"
        } else {
            Write-Diagnostic ("ICMP echo did not reply host={0}; this is informational because ICMP may be blocked." -f
                $serverHost) "WARN"
        }
    } catch {
        Write-Diagnostic ("ICMP echo could not run host={0}; this is not a TCP/TLS failure: {1}" -f
            $serverHost, $_.Exception.Message) "WARN"
    }

    $tcpHost = if ($ConnectAddress) { $ConnectAddress } else { $serverHost }
    try {
        $tcpResult = Test-NetConnection -ComputerName $tcpHost -Port $serverPort `
            -InformationLevel Detailed -WarningAction SilentlyContinue
        if ($tcpResult.TcpTestSucceeded) {
            Write-Diagnostic ("TCP reachable host={0} port={1} TcpTestSucceeded=True" -f
                $tcpHost, $serverPort) "PASS"
        } else {
            $failures.Add("TCP port $serverPort is not reachable at $tcpHost.")
            Write-Diagnostic ("TCP unreachable host={0} port={1} TcpTestSucceeded=False" -f
                $tcpHost, $serverPort) "FAIL"
        }
    } catch {
        $failures.Add("TCP test failed for ${tcpHost}:$serverPort.")
        Write-Diagnostic ("TCP test error host={0} port={1} reason={2}" -f
            $tcpHost, $serverPort, $_.Exception.Message) "FAIL"
    }

    $connectTarget = Get-ConnectTarget -HostName $serverHost -Port $serverPort `
        -AddressOverride $ConnectAddress
    $verifyOption = if ($hostIsIp) { "-verify_ip" } else { "-verify_hostname" }
    $tlsArguments = @(
        "s_client",
        "-brief",
        "-connect", $connectTarget
    )
    if (-not $hostIsIp) {
        $tlsArguments += @("-servername", $serverHost)
    }
    $tlsArguments += @(
        "-CAfile", $caPath,
        "-verify_return_error",
        $verifyOption, $serverHost
    )
    $tls = Invoke-OpenSsl -Arguments $tlsArguments
    $safeTlsLines = @($tls.Output -split "`r?`n" |
        Where-Object {
            $_ -match "^(CONNECTION ESTABLISHED|Protocol version:|Ciphersuite:|Peer certificate:|Hash used:|Signature type:|Verification:|Verify return code:)"
        })
    foreach ($line in $safeTlsLines) {
        Write-Diagnostic ("TLS {0}" -f $line.Trim())
    }
    $tlsVerified =
        $tls.Output -match "Verification:\s*OK" -or
        $tls.Output -match "Verify return code:\s*0\s*\(ok\)"
    if ($tlsVerified) {
        Write-Diagnostic ("TLS chain and {0} identity verification succeeded; sni={1}." -f
            $(if ($hostIsIp) { "IP SAN" } else { "hostname/SAN" }),
            $(if ($hostIsIp) { "not-applicable-to-ip-literal" } else { $serverHost })) "PASS"
    } else {
        $failures.Add("TLS verification failed.")
        Write-Diagnostic ("TLS verification failed exit_code={0}. Run Test-Certificate.ps1 for public certificate details." -f
            $tls.ExitCode) "FAIL"
    }

    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (-not $curl) {
        $failures.Add("curl.exe was not found.")
        Write-Diagnostic "curl.exe was not found; the verified HTTPS request was not run." "FAIL"
    } else {
        $curlVersion = ((& $curl.Source --version | Select-Object -First 1) -as [string])
        $usesSchannel = $curlVersion -match "\bSchannel\b"
        $curlArguments = @(
            "--cacert", $caPath,
            "--connect-timeout", "10",
            "--max-time", "20",
            "--silent",
            "--show-error",
            "--output", "NUL",
            "--write-out", "%{http_code}",
            "--noproxy", "*"
        )
        if ($usesSchannel) {
            # A private CA commonly has no Internet-reachable CRL. Schannel's
            # default hard failure for "revocation status unknown" would make
            # a verified private chain look broken. Best-effort still checks
            # available revocation data and retains CA/identity validation; it
            # is deliberately not the weaker --ssl-no-revoke option.
            $curlArguments += "--ssl-revoke-best-effort"
            Write-Diagnostic "curl uses Schannel; best-effort revocation is enabled for the private CA while CA-chain and identity verification remain mandatory." "INFO"
        }
        if ($ConnectAddress) {
            $curlArguments += @("--resolve", ("{0}:{1}:{2}" -f
                $serverHost, $serverPort, $ConnectAddress))
        }
        $curlArguments += $ServerUrl.AbsoluteUri
        $previousErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = "SilentlyContinue"
            $httpOutput = @(& $curl.Source @curlArguments 2>&1)
            $curlExit = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        $httpCode = (($httpOutput | ForEach-Object { [string]$_ }) -join "").Trim()
        if ($curlExit -eq 0 -and $httpCode -match "^[1-5][0-9][0-9]$") {
            Write-Diagnostic ("Verified HTTPS request completed status={0} proxy=disabled" -f
                $httpCode) "PASS"
        } else {
            $failures.Add("The verified HTTPS request failed.")
            Write-Diagnostic ("Verified HTTPS request failed curl_exit={0} status={1}" -f
                $curlExit, $(if ($httpCode) { $httpCode } else { "none" })) "FAIL"
        }
    }

    if ($ConnectAddress) {
        Write-Diagnostic ("ConnectAddress={0} was used only for transport; TLS still verified identity={1}." -f
            $ConnectAddress, $serverHost) "INFO"
    }
    if ($failures.Count -gt 0) {
        Write-Diagnostic ("Diagnostics failed checks={0}: {1}" -f
            $failures.Count, ($failures -join " ")) "FAIL"
        exit 1
    }

    Write-Diagnostic "All server connectivity, trust-chain, identity, and HTTPS checks passed." "PASS"
    exit 0
} catch {
    Write-Diagnostic ("Fatal diagnostic error: {0}" -f $_.Exception.Message) "FAIL"
    exit 1
}
