[CmdletBinding()]
param(
    [Uri]$SensorUrl = "http://192.168.4.1",

    [Parameter(Mandatory = $true)]
    [Uri]$ServerUrl,

    [Parameter(Mandatory = $true)]
    [string]$CaCertificatePath,

    [Parameter(Mandatory = $true)]
    [ValidateLength(1, 64)]
    [string]$FriendlyName,

    [Parameter(Mandatory = $true)]
    [ValidateLength(1, 32)]
    [string]$WifiSsid,

    [Security.SecureString]$WifiPassword,

    [Security.SecureString]$EnrollmentToken,

    [Security.SecureString]$AdministratorPassword,

    [ValidateSet("pull", "push", "hybrid")]
    [string]$ConnectionMode = "push",

    [ValidateRange(1, 1000)]
    [double]$CtRatingA = 100,

    [switch]$UseStaticIpv4,

    [string]$StaticIp = "",

    [string]$StaticGateway = "",

    [string]$StaticSubnet = "",

    [string]$StaticDns = "",

    [Uri]$PostProvisioningSensorUrl,

    [ValidateRange(10, 180)]
    [int]$VerificationTimeoutSeconds = 90,

    [string]$LogDirectory = (Join-Path ([Environment]::GetFolderPath("UserProfile")) "PowerMonitorDiagnostics")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-DiagnosticLog {
    param([string]$Directory)

    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    $resolved = (Resolve-Path -LiteralPath $Directory).Path
    return Join-Path $resolved ("sensor-provisioning-{0}.log" -f
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

function ConvertFrom-SecureValue {
    param([Security.SecureString]$Value)

    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Join-Endpoint {
    param([Uri]$Base, [string]$Path)

    $origin = $Base.GetLeftPart([UriPartial]::Authority).TrimEnd("/")
    return [Uri]($origin + $Path)
}

function Invoke-LocalJson {
    param(
        [Uri]$Uri,
        [ValidateSet("GET", "POST")]
        [string]$Method,
        [string]$Body = "",
        [string]$Csrf = "",
        [switch]$PreferAsync,
        [Net.CookieContainer]$Cookies
    )

    $request = [Net.HttpWebRequest]::Create($Uri)
    $request.Method = $Method
    $request.Accept = "application/json"
    $request.ContentType = "application/json"
    $request.Proxy = $null
    $request.AllowAutoRedirect = $false
    $request.Timeout = 10000
    $request.ReadWriteTimeout = 10000
    $request.CookieContainer = $Cookies
    if ($Csrf) {
        $request.Headers["X-PM-CSRF"] = $Csrf
    }
    if ($PreferAsync) {
        $request.Headers["Prefer"] = "respond-async"
    }
    if ($Method -eq "POST") {
        # Firmware rejects mutating browser/local-session traffic that omits
        # Origin. Use the exact authority being addressed; never invent a
        # hostname that differs from SensorUrl.
        $request.Headers["Origin"] = $Uri.GetLeftPart([UriPartial]::Authority)
        $bytes = [Text.Encoding]::UTF8.GetBytes($Body)
        $request.ContentLength = $bytes.Length
        $stream = $request.GetRequestStream()
        try {
            $stream.Write($bytes, 0, $bytes.Length)
        } finally {
            $stream.Dispose()
        }
    }

    $response = $null
    try {
        $response = [Net.HttpWebResponse]$request.GetResponse()
    } catch [Net.WebException] {
        if (-not $_.Exception.Response) {
            throw
        }
        $response = [Net.HttpWebResponse]$_.Exception.Response
    }
    try {
        $reader = [IO.StreamReader]::new($response.GetResponseStream())
        try {
            $responseBody = $reader.ReadToEnd()
        } finally {
            $reader.Dispose()
        }
        return [PSCustomObject]@{
            StatusCode = [int]$response.StatusCode
            Body = $responseBody
        }
    } finally {
        $response.Dispose()
    }
}

function Open-LocalSession {
    param([Uri]$Base, [Net.CookieContainer]$Cookies)

    $result = Invoke-LocalJson -Uri (Join-Endpoint -Base $Base -Path "/api/v1/auth/session") `
        -Method "POST" -Body "{}" -Cookies $Cookies
    if ($result.StatusCode -ne 200) {
        throw "The sensor refused local session creation with HTTP $($result.StatusCode)."
    }
    $document = $result.Body | ConvertFrom-Json
    if (-not $document.csrf) {
        throw "The sensor session response did not include a CSRF value."
    }
    return $document
}

function Get-JsonDocument {
    param([string]$Text, [string]$Description)

    try {
        return $Text | ConvertFrom-Json
    } catch {
        throw "$Description returned invalid JSON."
    }
}

function Test-PublicCa {
    param([string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $text = Get-Content -LiteralPath $resolved -Raw
    if ($text -match "-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----") {
        throw "The CA file contains private-key material. Use only the public root.crt."
    }
    $match = [regex]::Match(
        $text,
        "-----BEGIN CERTIFICATE-----\s*(?<body>[A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----",
        [Text.RegularExpressions.RegexOptions]::Singleline
    )
    if (-not $match.Success) {
        throw "The CA file does not contain a PEM certificate."
    }
    if ($text.Length -gt 8192) {
        throw "The CA PEM exceeds the sensor's 8192-byte limit."
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
    return $text.Trim()
}

function Test-LocalBaseUrl {
    param([Uri]$Value, [string]$Name)

    if ($Value.Scheme -ne "http") {
        throw "$Name must use local HTTP; the sensor UI does not expose HTTPS."
    }
    if ($Value.UserInfo -or $Value.Query -or $Value.Fragment) {
        throw "$Name must not contain credentials, a query string, or a fragment."
    }
}

function Wait-ForProvisioningResult {
    param(
        [Uri]$Base,
        [Net.CookieContainer]$Cookies,
        [string]$JobId,
        [int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $encodedJobId = [Uri]::EscapeDataString($JobId)
        $uri = Join-Endpoint -Base $Base `
            -Path ("/api/v1/auth/password-jobs?job_id={0}" -f $encodedJobId)
        $result = Invoke-LocalJson -Uri $uri -Method "GET" -Cookies $Cookies
        if ($result.StatusCode -eq 202) {
            Start-Sleep -Milliseconds 300
            continue
        }
        $document = Get-JsonDocument -Text $result.Body -Description "Password job"
        if ($result.StatusCode -ne 200) {
            $code = if ($document.code) { [string]$document.code } else { "unknown" }
            throw "Provisioning verification failed with HTTP $($result.StatusCode), code=$code."
        }
        if ($document.status -ne "setup_applied") {
            throw "The sensor returned an unexpected provisioning result."
        }
        return $true
    }
    throw "The sensor did not finish the bounded provisioning job before the timeout."
}

function Wait-ForPostProvisioningConfig {
    param(
        [Uri]$Base,
        [string]$ExpectedSsid,
        [Uri]$ExpectedServer,
        [int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastReason = "not attempted"
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $cookies = [Net.CookieContainer]::new()
            $session = Open-LocalSession -Base $Base -Cookies $cookies
            $configResponse = Invoke-LocalJson `
                -Uri (Join-Endpoint -Base $Base -Path "/api/v1/config") `
                -Method "GET" -Cookies $cookies
            $healthResponse = Invoke-LocalJson `
                -Uri (Join-Endpoint -Base $Base -Path "/api/v1/health") `
                -Method "GET" -Cookies $cookies
            if ($configResponse.StatusCode -ne 200 -or
                $healthResponse.StatusCode -ne 200) {
                throw "The post-provisioning API did not return HTTP 200."
            }
            $config = Get-JsonDocument -Text $configResponse.Body -Description "Configuration"
            $health = Get-JsonDocument -Text $healthResponse.Body -Description "Health"
            if ($config.wifi_ssid -ne $ExpectedSsid) {
                throw "The saved Wi-Fi SSID did not match the submitted value."
            }
            if ($config.server_url -ne $ExpectedServer.AbsoluteUri.TrimEnd("/")) {
                throw "The saved server URL did not match the submitted value."
            }
            if (-not $config.server_ca_configured) {
                throw "The saved configuration does not report a CA certificate."
            }
            if ($health.protocol -ne "pm-protocol/1.0.0") {
                throw "The sensor reported an unexpected protocol identifier."
            }
            return $health
        } catch {
            $lastReason = $_.Exception.Message
            Start-Sleep -Seconds 2
        }
    }
    throw "Post-provisioning verification timed out. Last result: $lastReason"
}

$script:LogPath = New-DiagnosticLog -Directory $LogDirectory
$payloadText = ""
$wifiPlain = ""
$tokenPlain = ""
$administratorPlain = ""

try {
    Write-Diagnostic "Starting sensor provisioning test. Log=$script:LogPath"
    Test-LocalBaseUrl -Value $SensorUrl -Name "SensorUrl"
    if ($PostProvisioningSensorUrl) {
        Test-LocalBaseUrl -Value $PostProvisioningSensorUrl `
            -Name "PostProvisioningSensorUrl"
    }
    if ($ServerUrl.Scheme -ne "https") {
        throw "ServerUrl must use HTTPS."
    }
    if ($ServerUrl.UserInfo -or $ServerUrl.Query -or $ServerUrl.Fragment) {
        throw "ServerUrl must not contain credentials, a query string, or a fragment."
    }
    if ($UseStaticIpv4) {
        foreach ($entry in @($StaticIp, $StaticGateway, $StaticSubnet, $StaticDns)) {
            $parsedAddress = $null
            if (-not [Net.IPAddress]::TryParse($entry, [ref]$parsedAddress) -or
                $parsedAddress.AddressFamily -ne
                    [Net.Sockets.AddressFamily]::InterNetwork) {
                throw "Static IPv4 mode requires valid address, gateway, subnet, and DNS values."
            }
        }
    }

    $caPem = Test-PublicCa -Path $CaCertificatePath
    $cookies = [Net.CookieContainer]::new()
    $session = Open-LocalSession -Base $SensorUrl -Cookies $cookies
    Write-Diagnostic ("Local session established setup_required={0} proxy=disabled secrets=redacted" -f
        [bool]$session.setup_required) "PASS"
    if (-not [bool]$session.setup_required) {
        Write-Diagnostic "The sensor is already provisioned; no credentials or settings were submitted." "WARN"
        $configResponse = Invoke-LocalJson `
            -Uri (Join-Endpoint -Base $SensorUrl -Path "/api/v1/config") `
            -Method "GET" -Cookies $cookies
        if ($configResponse.StatusCode -ne 200) {
            throw "The existing redacted configuration could not be read."
        }
        $config = Get-JsonDocument -Text $configResponse.Body -Description "Configuration"
        Write-Diagnostic ("Existing configuration protocol=pm-protocol/1.0.0 wifi_configured={0} server_configured={1} ca_configured={2}" -f
            [bool]([string]$config.wifi_ssid),
            [bool]([string]$config.server_url),
            [bool]$config.server_ca_configured) "PASS"
        exit 0
    }

    if (-not $WifiPassword) {
        $WifiPassword = Read-Host "Wi-Fi password (input hidden)" -AsSecureString
    }
    if (-not $EnrollmentToken) {
        $EnrollmentToken = Read-Host "One-time enrollment token (input hidden)" -AsSecureString
    }
    if (-not $AdministratorPassword) {
        $AdministratorPassword =
            Read-Host "New local administrator password (input hidden)" -AsSecureString
    }
    $wifiPlain = ConvertFrom-SecureValue -Value $WifiPassword
    $tokenPlain = ConvertFrom-SecureValue -Value $EnrollmentToken
    $administratorPlain = ConvertFrom-SecureValue -Value $AdministratorPassword
    if ($wifiPlain.Length -lt 8 -or $wifiPlain.Length -gt 63) {
        throw "The Wi-Fi password must contain 8 through 63 characters."
    }
    if ($tokenPlain.Length -lt 32 -or $tokenPlain.Length -gt 256) {
        throw "The enrollment token must contain 32 through 256 characters."
    }
    if ($administratorPlain.Length -lt 12 -or $administratorPlain.Length -gt 128) {
        throw "The administrator password must contain 12 through 128 characters."
    }

    $payload = [ordered]@{
        friendly_name = $FriendlyName
        wifi_ssid = $WifiSsid
        wifi_password = $wifiPlain
        static_network_enabled = [bool]$UseStaticIpv4
        static_ip = $(if ($UseStaticIpv4) { $StaticIp } else { "" })
        static_gateway = $(if ($UseStaticIpv4) { $StaticGateway } else { "" })
        static_subnet = $(if ($UseStaticIpv4) { $StaticSubnet } else { "" })
        static_dns = $(if ($UseStaticIpv4) { $StaticDns } else { "" })
        server_url = $ServerUrl.AbsoluteUri.TrimEnd("/")
        server_ca_pem = $caPem
        server_fingerprint = ""
        enrollment_token = $tokenPlain
        admin_password = $administratorPlain
        connection_mode = $ConnectionMode
        ct_rating_a = $CtRatingA
    }
    $payloadText = $payload | ConvertTo-Json -Compress
    Write-Diagnostic ("Submitting first-run setup fields wifi_ssid=provided server_url={0} ca=public_pem token=redacted passwords=redacted" -f
        $payload.server_url)
    $queued = Invoke-LocalJson `
        -Uri (Join-Endpoint -Base $SensorUrl -Path "/api/v1/setup/apply") `
        -Method "POST" -Body $payloadText -Csrf ([string]$session.csrf) `
        -PreferAsync -Cookies $cookies
    $payloadText = ""
    $payload = $null
    $wifiPlain = ""
    $tokenPlain = ""
    $administratorPlain = ""
    if ($queued.StatusCode -ne 202) {
        $problem = Get-JsonDocument -Text $queued.Body -Description "Setup response"
        $code = if ($problem.code) { [string]$problem.code } else { "unknown" }
        throw "The sensor rejected setup with HTTP $($queued.StatusCode), code=$code."
    }
    $job = Get-JsonDocument -Text $queued.Body -Description "Setup queue response"
    if (-not $job.job_id) {
        throw "The sensor did not return a bounded setup job identifier."
    }
    Write-Diagnostic "Setup was accepted into the bounded password/persistence worker; job identifier redacted." "PASS"

    try {
        Wait-ForProvisioningResult -Base $SensorUrl -Cookies $cookies `
            -JobId ([string]$job.job_id) -TimeoutSeconds 25 | Out-Null
    } catch {
        if (-not $PostProvisioningSensorUrl) {
            throw
        }
        Write-Diagnostic "The setup address disconnected while settings were being applied; switching to the post-provisioning address." "WARN"
        $newCookies = [Net.CookieContainer]::new()
        $newSession = $null
        $sessionDeadline = [DateTime]::UtcNow.AddSeconds($VerificationTimeoutSeconds)
        while (-not $newSession -and [DateTime]::UtcNow -lt $sessionDeadline) {
            try {
                $newSession = Open-LocalSession -Base $PostProvisioningSensorUrl `
                    -Cookies $newCookies
            } catch {
                Start-Sleep -Seconds 2
            }
        }
        if (-not $newSession) {
            throw "The sensor did not become reachable at PostProvisioningSensorUrl."
        }
        Wait-ForProvisioningResult -Base $PostProvisioningSensorUrl `
            -Cookies $newCookies -JobId ([string]$job.job_id) `
            -TimeoutSeconds 25 | Out-Null
    }
    Write-Diagnostic "The sensor reported that setup persistence and readback verification succeeded." "PASS"

    if ($PostProvisioningSensorUrl) {
        $health = Wait-ForPostProvisioningConfig `
            -Base $PostProvisioningSensorUrl `
            -ExpectedSsid $WifiSsid `
            -ExpectedServer $ServerUrl `
            -TimeoutSeconds $VerificationTimeoutSeconds
        Write-Diagnostic ("Post-provisioning API verified protocol={0} wifi_connected={1} server_reachable={2}" -f
            [string]$health.protocol,
            [bool]$health.wifi.connected,
            [bool]$health.server.reachable) "PASS"
    } else {
        Write-Diagnostic "No PostProvisioningSensorUrl was supplied; station-mode reachability must be checked separately." "WARN"
    }
    Write-Diagnostic "Provisioning test completed without printing or storing submitted secrets." "PASS"
    exit 0
} catch {
    Write-Diagnostic ("Provisioning test failed: {0}" -f $_.Exception.Message) "FAIL"
    exit 1
} finally {
    $payloadText = ""
    $wifiPlain = ""
    $tokenPlain = ""
    $administratorPlain = ""
}
