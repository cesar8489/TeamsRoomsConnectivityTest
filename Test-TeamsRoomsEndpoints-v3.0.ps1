<#
.SYNOPSIS
    Tests network connectivity from this PC to the Microsoft Teams and Teams
    Rooms (Windows + Android) cloud endpoints - core Teams client/sign-in
    services, the Teams Rooms Pro Management Portal (Azure IoT Hub, Web
    PubSub, agent), Microsoft Store, telemetry, Intune, and real-time media.

.DESCRIPTION
    Always tests both device platforms (Windows + Android), the core Teams /
    Microsoft 365 sign-in endpoints, and the documented Commercial/Worldwide
    management portal hosts - just run it. GCC, GCC High, DoD, 21Vianet, and
    other government or sovereign clouds are out of scope.

    For each required endpoint the script performs:
      * DNS resolution
      * TCP connectivity on the relevant port(s)
      * TLS 1.2 handshake validation on port 443 (Teams devices require TLS 1.2+)

    Endpoint tests run in parallel (bounded by -MaxParallel) so the total run
    time is close to the slowest single endpoint rather than the sum of all of
    them, which matters most when some endpoints are firewalled and time out.

    A self-contained HTML report is written to disk and opened in the default
    browser, summarising results and recommended remediation actions.

    Runs entirely in user context. NO administrator rights are required.

.PARAMETER TimeoutSeconds
    Per-connection timeout. Default = 5 seconds.

.PARAMETER OutputPath
    Path for the HTML report. Defaults to a timestamped file next to the script.

.PARAMETER NoBrowser
    Do not automatically open the report when finished.

.PARAMETER SkipMedia
    Skip the real-time media relay (UDP/STUN) reachability test.

.PARAMETER MediaRelayHost
    FQDN of the Teams transport relay to probe for media. Default =
    worldaz.tr.teams.microsoft.com (Microsoft anycast relay, 52.112/52.122).

.PARAMETER MediaPorts
    UDP ports to probe for media traffic. Default = 3478 only (the Teams relay's
    STUN-authoritative media port). Pass a range like (3478..3481) to test more.

.PARAMETER MaxParallel
    Maximum number of endpoints tested concurrently. Default = 12. Set to 1 to
    force fully sequential testing.

.EXAMPLE
    .\Test-TeamsRoomsEndpoints-v3.0.ps1

.NOTES
    Version: 3.0
#>

[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 5,

    [string]$OutputPath,

    [switch]$NoBrowser,

    [switch]$SkipMedia,

    [string]$MediaRelayHost = 'worldaz.tr.teams.microsoft.com',

    [int[]]$MediaPorts = (3478),

    [int]$MediaProbeCount = 20,

    [switch]$SkipNtp,

    [switch]$SkipProxyCheck,

    [int]$MaxParallel = 12
)

$ErrorActionPreference = 'Stop'

# Version stamp - bump whenever the script changes.
$ScriptVersion = '3.0'

# ---------------------------------------------------------------------------
# Endpoint catalogue
# ---------------------------------------------------------------------------
# Port meanings:
#   443  = HTTPS / MQTT+AMQP over WebSockets (Azure IoT Hub, Web PubSub, web)
#   5671 = AMQP (Azure IoT Hub)
#   8883 = MQTT  (Azure IoT Hub)
# ---------------------------------------------------------------------------

$IoTPorts    = @(443, 5671, 8883)
$WebPorts    = @(443)
$StorePorts  = @(443, 80)
$CorePorts   = @(443)
$HttpPort    = @(80)

function New-Endpoint {
    param(
        [string]$HostName,
        [int[]]$Ports,
        [string]$Category,
        [string]$DevicePlatform,   # Windows | Android | Both
        [string]$DeviceCloud,      # Commercial
        [string]$Purpose,
        [bool]$CheckPublicDns = $false,
        [int[]]$AdvisoryPorts = @()
    )
    [pscustomobject]@{
        Host           = $HostName
        Ports          = $Ports
        Category       = $Category
        Platform       = $DevicePlatform
        Cloud          = $DeviceCloud
        Purpose        = $Purpose
        CheckPublicDns = $CheckPublicDns
        AdvisoryPorts  = $AdvisoryPorts
    }
}

$catalogue = @(
    # === Core Teams / Microsoft 365 (client sign-in & core service) ========
    # Always included. These are the essential Microsoft 365 / Teams client
    # endpoints (from the published Microsoft 365 URLs and IP address ranges,
    # Microsoft Teams service area) needed for the Teams app itself - not just
    # the Rooms Pro Management Portal - to sign in and operate. Applies to
    # Windows and Android alike.
    New-Endpoint 'login.microsoftonline.com'         $CorePorts 'Core Teams' 'Both' 'Commercial' 'Microsoft Entra ID sign-in'
    New-Endpoint 'login.microsoft.com'                $CorePorts 'Core Teams' 'Both' 'Commercial' 'Microsoft Entra ID sign-in (alt)'
    New-Endpoint 'device.login.microsoftonline.com'   $CorePorts 'Core Teams' 'Both' 'Commercial' 'Device-code sign-in (Rooms/console auth)'
    New-Endpoint 'accounts.accesscontrol.windows.net' $CorePorts 'Core Teams' 'Both' 'Commercial' 'Azure AD access control token service'
    New-Endpoint 'graph.microsoft.com'                $CorePorts 'Core Teams' 'Both' 'Commercial' 'Microsoft Graph API'
    New-Endpoint 'teams.microsoft.com'                $CorePorts 'Core Teams' 'Both' 'Commercial' 'Teams client / core service'
    New-Endpoint 'teams.cloud.microsoft'              $CorePorts 'Core Teams' 'Both' 'Commercial' 'Teams unified domain (Microsoft 365 consolidation)'
    New-Endpoint 'aka.ms'                             $WebPorts  'Core Teams' 'Both' 'Commercial' 'Short-link redirector used by the Teams client'
    New-Endpoint 'join.secure.skypeassets.com'        $WebPorts  'Core Teams' 'Both' 'Commercial' 'Teams/Skype asset delivery' $true
    New-Endpoint 'mlccdnprod.azureedge.net'           $WebPorts  'Core Teams' 'Both' 'Commercial' 'Teams meeting/live-event CDN' $true

    # === Windows ============================================================
    # --- Microsoft Store API (AppInstallManager) - TCP 80 & 443 -------------
    New-Endpoint 'displaycatalog.mp.microsoft.com'  $StorePorts 'Microsoft Store' 'Windows' 'Commercial' 'Store catalog (AppInstallManager)'
    New-Endpoint 'purchase.md.mp.microsoft.com'     $StorePorts 'Microsoft Store' 'Windows' 'Commercial' 'Store purchase (AppInstallManager)'
    New-Endpoint 'licensing.mp.microsoft.com'       $StorePorts 'Microsoft Store' 'Windows' 'Commercial' 'Store licensing (AppInstallManager)' $false @(80)
    New-Endpoint 'storeedgefd.dsx.mp.microsoft.com' $StorePorts 'Microsoft Store' 'Windows' 'Commercial' 'Store edge front door (AppInstallManager)'

    # --- Windows Update (concrete hosts from the WSUS allow list) -----------
    # Microsoft also publishes wildcard domains. Wildcards cannot be probed
    # directly, so these checks cover the concrete hosts named in the guidance.
    New-Endpoint 'windowsupdate.microsoft.com'  $HttpPort   'Windows Update' 'Windows' 'Commercial' 'Windows Update service'
    New-Endpoint 'download.windowsupdate.com'   $HttpPort   'Windows Update' 'Windows' 'Commercial' 'Windows Update downloads'
    New-Endpoint 'download.microsoft.com'       $WebPorts   'Windows Update' 'Windows' 'Commercial' 'Microsoft update downloads'
    New-Endpoint 'ntservicepack.microsoft.com'  $HttpPort   'Windows Update' 'Windows' 'Commercial' 'Windows service pack downloads'
    New-Endpoint 'go.microsoft.com'             $HttpPort   'Windows Update' 'Windows' 'Commercial' 'Microsoft redirect service'
    New-Endpoint 'dl.delivery.mp.microsoft.com' $StorePorts 'Windows Update' 'Windows' 'Commercial' 'Windows Update delivery service'

    # --- Telemetry ----------------------------------------------------------
    New-Endpoint 'vortex.data.microsoft.com'        $WebPorts 'Telemetry' 'Windows' 'Commercial' 'Telemetry client endpoint'
    New-Endpoint 'settings.data.microsoft.com'      $WebPorts 'Telemetry' 'Windows' 'Commercial' 'Telemetry settings endpoint'

    # --- Management Portal: agent -------------------------------------------
    New-Endpoint 'agent.rooms.microsoft.com'        $WebPorts 'Management Portal' 'Windows' 'Commercial' 'Teams Rooms Pro management agent'

    # --- Management Portal: Azure IoT Hub -----------------------------------
    New-Endpoint 'mmrstgnoamiot.azure-devices.net'  $IoTPorts 'Azure IoT Hub' 'Windows' 'Commercial' 'IoT Hub (staging NOAM)'
    New-Endpoint 'mmrprodnoamiot.azure-devices.net' $IoTPorts 'Azure IoT Hub' 'Windows' 'Commercial' 'IoT Hub (prod NOAM)'
    New-Endpoint 'mmrprodemeaiot.azure-devices.net' $IoTPorts 'Azure IoT Hub' 'Windows' 'Commercial' 'IoT Hub (prod EMEA)'
    New-Endpoint 'mmrprodapaciot.azure-devices.net' $IoTPorts 'Azure IoT Hub' 'Windows' 'Commercial' 'IoT Hub (prod APAC)'

    # --- Management Portal: Azure Web PubSub --------------------------------
    New-Endpoint 'mmrprodnoampubsub.webpubsub.azure.com' $WebPorts 'Azure Web PubSub' 'Windows' 'Commercial' 'Web PubSub (NOAM)'
    New-Endpoint 'mmrprodemeapubsub.webpubsub.azure.com' $WebPorts 'Azure Web PubSub' 'Windows' 'Commercial' 'Web PubSub (EMEA)'
    New-Endpoint 'mmrprodapacpubsub.webpubsub.azure.com' $WebPorts 'Azure Web PubSub' 'Windows' 'Commercial' 'Web PubSub (APAC)'

    # === Android ============================================================
    # --- Management Portal: Azure IoT Hub (per device class & region) -------
    New-Endpoint 'mmrprodnoamcbiot.azure-devices.net'     $IoTPorts 'Azure IoT Hub' 'Android' 'Commercial' 'IoT Hub NOAM - conference bar'
    New-Endpoint 'mmrprodnoamtciot.azure-devices.net'     $IoTPorts 'Azure IoT Hub' 'Android' 'Commercial' 'IoT Hub NOAM - touch console'
    New-Endpoint 'mmrprodnoamphonesiot.azure-devices.net' $IoTPorts 'Azure IoT Hub' 'Android' 'Commercial' 'IoT Hub NOAM - phones'
    New-Endpoint 'mmrprodnoampanelsiot.azure-devices.net' $IoTPorts 'Azure IoT Hub' 'Android' 'Commercial' 'IoT Hub NOAM - panels'
    New-Endpoint 'mmrprodemeacbiot.azure-devices.net'     $IoTPorts 'Azure IoT Hub' 'Android' 'Commercial' 'IoT Hub EMEA - conference bar'
    New-Endpoint 'mmrprodemeatciot.azure-devices.net'     $IoTPorts 'Azure IoT Hub' 'Android' 'Commercial' 'IoT Hub EMEA - touch console'
    New-Endpoint 'mmrprodemeaphonesiot.azure-devices.net' $IoTPorts 'Azure IoT Hub' 'Android' 'Commercial' 'IoT Hub EMEA - phones'
    New-Endpoint 'mmrprodemeapanelsiot.azure-devices.net' $IoTPorts 'Azure IoT Hub' 'Android' 'Commercial' 'IoT Hub EMEA - panels'
    New-Endpoint 'mmrprodapaccbiot.azure-devices.net'     $IoTPorts 'Azure IoT Hub' 'Android' 'Commercial' 'IoT Hub APAC - conference bar'
    New-Endpoint 'mmrprodapactciot.azure-devices.net'     $IoTPorts 'Azure IoT Hub' 'Android' 'Commercial' 'IoT Hub APAC - touch console'
    New-Endpoint 'mmrprodapacphonesiot.azure-devices.net' $IoTPorts 'Azure IoT Hub' 'Android' 'Commercial' 'IoT Hub APAC - phones'
    New-Endpoint 'mmrprodapacpanelsiot.azure-devices.net' $IoTPorts 'Azure IoT Hub' 'Android' 'Commercial' 'IoT Hub APAC - panels'

    # --- Microsoft Intune (required by both platform guidance pages) --------
    New-Endpoint 'manage.microsoft.com'             $WebPorts 'Microsoft Intune' 'Both' 'Commercial' 'Intune device management'

)

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------
# Every entry applies to Windows, Android, or both and uses the Commercial /
# Worldwide cloud. Government and sovereign clouds are out of scope.
$targets = $catalogue

if (-not $targets) {
    Write-Warning "No endpoints found to test."
    return
}

# ---------------------------------------------------------------------------
# Test helpers (no admin required)
# ---------------------------------------------------------------------------
function Test-Dns {
    param([string]$HostName)
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($HostName) |
            ForEach-Object { $_.IPAddressToString }
        return [pscustomobject]@{ Success = $true; Addresses = ($addrs -join ', ') }
    }
    catch {
        return [pscustomobject]@{ Success = $false; Addresses = $_.Exception.Message }
    }
}

function Test-PublicDns {
    param([string]$HostName, [int]$Timeout)

    $escapedHost = [System.Uri]::EscapeDataString($HostName)
    $resolvers = @(
        [pscustomobject]@{ Name = 'Google'; Uri = "https://dns.google/resolve?name=$escapedHost&type=A" }
        [pscustomobject]@{ Name = 'Cloudflare'; Uri = "https://cloudflare-dns.com/dns-query?name=$escapedHost&type=A" }
    )
    $checks = @()
    foreach ($resolver in $resolvers) {
        try {
            $response = Invoke-RestMethod -Uri $resolver.Uri -Method Get `
                -Headers @{ Accept = 'application/dns-json' } -TimeoutSec $Timeout
            $status = [int]$response.Status
            $state = switch ($status) {
                0 { if (@($response.Answer).Count -gt 0) { 'Resolved' } else { 'No A record' } }
                2 { 'SERVFAIL' }
                3 { 'NXDOMAIN' }
                default { "DNS status $status" }
            }
            $checks += [pscustomobject]@{
                Resolver = $resolver.Name
                QueryOk  = $true
                Status   = $status
                State    = $state
            }
        }
        catch {
            $checks += [pscustomobject]@{
                Resolver = $resolver.Name
                QueryOk  = $false
                Status   = $null
                State    = $_.Exception.Message
            }
        }
    }

    $confirmedUnavailable =
        @($checks).Count -eq $resolvers.Count -and
        @($checks | Where-Object { -not $_.QueryOk -or $_.Status -notin 2, 3 }).Count -eq 0
    $detail = ($checks | ForEach-Object { "$($_.Resolver): $($_.State)" }) -join '; '
    [pscustomobject]@{ ConfirmedUnavailable = $confirmedUnavailable; Detail = $detail }
}

function Test-TcpPort {
    param([string]$HostName, [int]$Port, [int]$Timeout)
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $iar = $client.BeginConnect($HostName, $Port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($Timeout))) {
            $client.EndConnect($iar)
            return [pscustomobject]@{ Success = $true; Detail = 'Connected' }
        }
        return [pscustomobject]@{ Success = $false; Detail = "Timeout after ${Timeout}s" }
    }
    catch {
        return [pscustomobject]@{ Success = $false; Detail = $_.Exception.Message }
    }
    finally {
        $client.Close()
    }
}

function Test-Tls12 {
    param([string]$HostName, [int]$Port, [int]$Timeout)

    # Public CAs legitimately used by Microsoft / Azure endpoints.
    $trustedCa = @(
        'DigiCert', 'Microsoft', 'Baltimore', 'Entrust', 'GlobalSign',
        'GeoTrust', 'Sectigo', 'Amazon', 'Actalis', 'IdenTrust'
    )
    # Well-known SSL-inspection / DPI proxy vendors.
    $inspectVendors = @(
        'Zscaler', 'Netskope', 'Palo Alto', 'PAN-', 'Fortinet', 'FortiGate',
        'Blue Coat', 'BlueCoat', 'Symantec Web', 'McAfee', 'Cisco', 'Umbrella',
        'Forcepoint', 'Sophos', 'Check Point', 'Checkpoint', 'Barracuda',
        'WatchGuard', 'Trend Micro', 'Menlo', 'iboss', 'Squid', 'Proxy',
        'SSL Inspection', 'Deep Packet', 'Firewall', 'Kaspersky', 'ESET',
        'Bitdefender', 'Sangfor', 'Untangle', 'pfSense', 'Fiddler', 'Charles',
        'BurpSuite', 'Burp'
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $iar = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($Timeout))) {
            return [pscustomobject]@{ Success = $false; Detail = 'TCP timeout'; Protocol = ''; Expiry = ''; Issuer = ''; Inspection = 'Unknown'; InspectionDetail = ''; ModernTls = $false }
        }
        $client.EndConnect($iar)

        $ssl = [System.Net.Security.SslStream]::new(
            $client.GetStream(), $false,
            { param($s, $cert, $chain, $errors) $true }
        )
        # Use the operating-system defaults, then reject a negotiated protocol
        # below TLS 1.2 when calculating the endpoint's overall status.
        $ssl.AuthenticateAsClient(
            $HostName, $null,
            [System.Security.Authentication.SslProtocols]::None,
            $false
        )
        $cert   = [System.Security.Cryptography.X509Certificates.X509Certificate2]$ssl.RemoteCertificate
        $expiry = if ($cert) { $cert.NotAfter.ToString('yyyy-MM-dd') } else { '' }
        $proto  = $ssl.SslProtocol.ToString()
        $modernTls = ($proto -match 'Tls12|Tls13')

        # --- SSL inspection / DPI detection via certificate chain -----------
        $issuerText = ''
        $rootText   = ''
        if ($cert) {
            $issuerText = $cert.Issuer
            try {
                $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
                $chain.ChainPolicy.RevocationMode = 'NoCheck'
                [void]$chain.Build($cert)
                if ($chain.ChainElements.Count -gt 0) {
                    $rootText = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Subject
                }
                $chain.Dispose()
            } catch { }
        }
        $ssl.Dispose()

        $combined = "$issuerText $rootText"
        $vendorHit = $inspectVendors | Where-Object { $combined -match [regex]::Escape($_) } | Select-Object -First 1
        $trustedHit = $trustedCa   | Where-Object { $combined -match [regex]::Escape($_) } | Select-Object -First 1

        # Short issuer label (CN, else O) for display.
        $issuerLabel = $issuerText
        if ($issuerText -match 'CN=([^,]+)') { $issuerLabel = $matches[1] }
        elseif ($issuerText -match 'O=([^,]+)') { $issuerLabel = $matches[1] }

        $inspection =
            if ($vendorHit)   { 'Detected' }
            elseif ($trustedHit) { 'None' }
            else              { 'Suspected' }

        $inspDetail =
            if ($vendorHit)   { "Certificate re-signed by '$vendorHit' - SSL/DPI interception" }
            elseif ($trustedHit) { "Public CA ($trustedHit) - no interception" }
            else              { "Unrecognized issuer '$issuerLabel' - possible interception" }

        return [pscustomobject]@{
            Success = $true; Detail = "TLS OK ($proto)"; Protocol = $proto; Expiry = $expiry
            Issuer = $issuerLabel; Inspection = $inspection; InspectionDetail = $inspDetail
            ModernTls = $modernTls
        }
    }
    catch {
        return [pscustomobject]@{ Success = $false; Detail = $_.Exception.Message; Protocol = ''; Expiry = ''; Issuer = ''; Inspection = 'Unknown'; InspectionDetail = $_.Exception.Message; ModernTls = $false }
    }
    finally {
        $client.Close()
    }
}

function Test-StunUdp {
    # Sends a STUN Binding Request and waits for a Binding Success Response.
    # A valid response proves outbound UDP media traffic reaches the relay.
    param([string]$HostName, [int]$Port, [int]$TimeoutMs = 2000)
    $udp = [System.Net.Sockets.UdpClient]::new()
    try {
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Connect($HostName, $Port)

        $req = New-Object byte[] 20
        $req[0] = 0x00; $req[1] = 0x01          # Binding Request
        $req[2] = 0x00; $req[3] = 0x00          # Message length = 0
        $req[4] = 0x21; $req[5] = 0x12; $req[6] = 0xA4; $req[7] = 0x42  # Magic cookie
        $tid = New-Object byte[] 12
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($tid)
        [Array]::Copy($tid, 0, $req, 8, 12)

        [void]$udp.Send($req, $req.Length)
        $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $resp = $udp.Receive([ref]$remote)

        if ($resp.Length -ge 20 -and $resp[0] -eq 0x01 -and $resp[1] -eq 0x01) {
            $mapped = ''
            $i = 20
            while ($i + 4 -le $resp.Length) {
                $attrType = ($resp[$i] -shl 8) -bor $resp[$i + 1]
                $attrLen  = ($resp[$i + 2] -shl 8) -bor $resp[$i + 3]
                if ($attrType -eq 0x0020 -and $attrLen -ge 8) {   # XOR-MAPPED-ADDRESS
                    $p  = (($resp[$i + 6] -shl 8) -bor $resp[$i + 7]) -bxor 0x2112
                    $a1 = $resp[$i + 8]  -bxor 0x21
                    $a2 = $resp[$i + 9]  -bxor 0x12
                    $a3 = $resp[$i + 10] -bxor 0xA4
                    $a4 = $resp[$i + 11] -bxor 0x42
                    $mapped = "$a1.$a2.$a3.$a4`:$p"
                    break
                }
                $i += 4 + $attrLen + ((4 - ($attrLen % 4)) % 4)
            }
            $detail = if ($mapped) { "STUN OK - mapped $mapped" } else { 'STUN response received' }
            return [pscustomobject]@{ Success = $true; Detail = $detail }
        }
        return [pscustomobject]@{ Success = $true; Detail = 'UDP response received' }
    }
    catch {
        return [pscustomobject]@{ Success = $false; Detail = 'No response (blocked/timeout)' }
    }
    finally {
        $udp.Close()
    }
}

function Measure-MediaQuality {
    # Sends repeated STUN Binding Requests to measure latency, jitter and loss.
    param([string]$HostName, [int]$Port, [int]$Count, [int]$TimeoutMs = 1000)
    $rtts = New-Object System.Collections.Generic.List[double]
    $sent = 0; $recv = 0
    for ($n = 0; $n -lt $Count; $n++) {
        $udp = [System.Net.Sockets.UdpClient]::new()
        try {
            $udp.Client.ReceiveTimeout = $TimeoutMs
            $udp.Connect($HostName, $Port)
            $req = New-Object byte[] 20
            $req[0] = 0x00; $req[1] = 0x01
            $req[4] = 0x21; $req[5] = 0x12; $req[6] = 0xA4; $req[7] = 0x42
            $tid = New-Object byte[] 12
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($tid)
            [Array]::Copy($tid, 0, $req, 8, 12)
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            [void]$udp.Send($req, $req.Length)
            $sent++
            $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            $resp = $udp.Receive([ref]$remote)
            $sw.Stop()
            if ($resp.Length -ge 20) { $recv++; $rtts.Add($sw.Elapsed.TotalMilliseconds) }
        }
        catch { }
        finally { $udp.Close() }
        # Space probes so the anycast relay doesn't rate-limit rapid bursts
        # (which would inflate apparent packet loss).
        [System.Threading.Thread]::Sleep(50)
    }

    if ($rtts.Count -eq 0) {
        return [pscustomobject]@{ Sent = $sent; Received = 0; LossPct = 100; MinMs = 0; AvgMs = 0; MaxMs = 0; JitterMs = 0 }
    }
    $avg = ($rtts | Measure-Object -Average).Average
    # Mean absolute deviation as a simple jitter estimate.
    $jitter = ($rtts | ForEach-Object { [math]::Abs($_ - $avg) } | Measure-Object -Average).Average
    $loss = [math]::Round((($sent - $recv) / [double]$sent) * 100, 1)
    return [pscustomobject]@{
        Sent = $sent; Received = $recv; LossPct = $loss
        MinMs = [math]::Round(($rtts | Measure-Object -Minimum).Minimum, 1)
        AvgMs = [math]::Round($avg, 1)
        MaxMs = [math]::Round(($rtts | Measure-Object -Maximum).Maximum, 1)
        JitterMs = [math]::Round($jitter, 1)
    }
}

function Test-Ntp {
    # Queries an NTP server (UDP 123) and returns reachability + clock offset.
    param([string]$Server = 'time.windows.com', [int]$TimeoutMs = 3000)
    $udp = [System.Net.Sockets.UdpClient]::new()
    try {
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Connect($Server, 123)
        $ntp = New-Object byte[] 48
        $ntp[0] = 0x1B   # LI=0, VN=3, Mode=3 (client)
        $t0 = [DateTime]::UtcNow
        [void]$udp.Send($ntp, $ntp.Length)
        $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $resp = $udp.Receive([ref]$remote)
        $t3 = [DateTime]::UtcNow
        if ($resp.Length -ge 48) {
            # Transmit timestamp starts at byte 40 (seconds since 1900).
            $intPart = ([uint32]$resp[40] -shl 24) -bor ([uint32]$resp[41] -shl 16) -bor ([uint32]$resp[42] -shl 8) -bor [uint32]$resp[43]
            $fracPart = ([uint32]$resp[44] -shl 24) -bor ([uint32]$resp[45] -shl 16) -bor ([uint32]$resp[46] -shl 8) -bor [uint32]$resp[47]
            $seconds = [double]$intPart + ([double]$fracPart / 4294967296.0)
            $epoch = [DateTime]::new(1900, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
            $serverUtc = $epoch.AddSeconds($seconds)
            $localMid = $t0.AddMilliseconds(($t3 - $t0).TotalMilliseconds / 2)
            $offset = [math]::Round(($serverUtc - $localMid).TotalSeconds, 2)
            return [pscustomobject]@{ Success = $true; Server = $Server; ServerUtc = $serverUtc; OffsetSec = $offset; Detail = "Reachable, offset ${offset}s" }
        }
        return [pscustomobject]@{ Success = $false; Server = $Server; ServerUtc = $null; OffsetSec = $null; Detail = 'Invalid NTP response' }
    }
    catch {
        return [pscustomobject]@{ Success = $false; Server = $Server; ServerUtc = $null; OffsetSec = $null; Detail = 'No response (UDP 123 blocked/timeout)' }
    }
    finally {
        $udp.Close()
    }
}

function Get-ProxyConfig {
    # Reads WinINET (per-user) and WinHTTP (system) proxy settings. No admin needed.
    $result = [pscustomobject]@{
        WinInetEnabled = $false; WinInetServer = ''; AutoConfigUrl = ''; AutoDetect = $false
        WinHttp = ''; HasProxy = $false
    }
    try {
        $reg = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
        $result.WinInetEnabled = ([int]$reg.ProxyEnable -eq 1)
        if ($reg.ProxyServer)   { $result.WinInetServer = [string]$reg.ProxyServer }
        if ($reg.AutoConfigURL) { $result.AutoConfigUrl = [string]$reg.AutoConfigURL }
        if ($null -ne $reg.DefaultConnectionSettings) {
            # Byte 8, bit flags: 0x08 = AutoDetect (WPAD)
            try { $result.AutoDetect = (([byte[]]$reg.DefaultConnectionSettings)[8] -band 0x08) -ne 0 } catch { }
        }
    } catch { }
    try {
        $wh = (netsh winhttp show proxy) 2>$null | Out-String
        if ($wh -match 'Proxy Server\(s\)\s*:\s*(.+)') { $result.WinHttp = $matches[1].Trim() }
        elseif ($wh -match 'Direct access') { $result.WinHttp = 'Direct access (no proxy)' }
    } catch { }
    $result.HasProxy = ($result.WinInetEnabled -and $result.WinInetServer) -or
                       [bool]$result.AutoConfigUrl -or $result.AutoDetect -or
                       ($result.WinHttp -and $result.WinHttp -notmatch 'Direct access')
    return $result
}

# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------
$results = New-Object System.Collections.Generic.List[object]
$targets = @($targets)
$total   = $targets.Count

Write-Host ""
Write-Host "Teams Rooms endpoint connectivity test (v$ScriptVersion)" -ForegroundColor Cyan
Write-Host "Platform=Both  Cloud=Commercial/Worldwide  Timeout=${TimeoutSeconds}s  Endpoints=$total" -ForegroundColor DarkGray
Write-Host "Out of scope: GCC, GCC High, DoD, 21Vianet/China, and other government or sovereign clouds" -ForegroundColor DarkGray
Write-Host ("-" * 60)

# Endpoints are tested concurrently (bounded by -MaxParallel) using a runspace
# pool so total run time tracks the slowest single endpoint rather than the
# sum of every endpoint's DNS/TCP/TLS timeouts. Purely in-process - no admin
# rights, new processes, or external modules required.
$poolSize = [Math]::Max(1, [Math]::Min($MaxParallel, $total))
$iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
foreach ($fnName in 'Test-Dns', 'Test-PublicDns', 'Test-TcpPort', 'Test-Tls12') {
    $fnEntry = [System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new(
        $fnName, (Get-Item "function:$fnName").ScriptBlock)
    $iss.Commands.Add($fnEntry)
}
$pool = [runspacefactory]::CreateRunspacePool(1, $poolSize, $iss, $Host)
$pool.Open()

$probe = {
    param($Endpoint, $Timeout)
    $dns = Test-Dns -HostName $Endpoint.Host
    $publicDns = $null
    # NOTE: intentionally using a plain array (not
    # System.Collections.Generic.List[object]) here. When two or more
    # functions are registered into a runspace pool's InitialSessionState via
    # SessionStateFunctionEntry, calling List[object].Add() from inside a
    # loop in the pooled scriptblock unpredictably throws
    # "System.ArgumentException: Argument types do not match" - a
    # runspace-pool/generic-collection type-resolution quirk. Plain arrays
    # do not trigger it.
    $portResults = @()
    $tls = $null
    if ($dns.Success) {
        foreach ($port in $Endpoint.Ports) {
            $tcp = Test-TcpPort -HostName $Endpoint.Host -Port $port -Timeout $Timeout
            $portResults += [pscustomobject]@{
                Port     = $port
                Success  = $tcp.Success
                Detail   = $tcp.Detail
                Advisory = ($Endpoint.AdvisoryPorts -contains $port)
            }
        }
        if ($Endpoint.Ports -contains 443) {
            $tls = Test-Tls12 -HostName $Endpoint.Host -Port 443 -Timeout $Timeout
        }
    }
    elseif ($Endpoint.CheckPublicDns) {
        $publicDns = Test-PublicDns -HostName $Endpoint.Host -Timeout $Timeout
    }
    [pscustomobject]@{ Dns = $dns; PublicDns = $publicDns; Ports = @($portResults); Tls = $tls }
}

try {
    $jobs = foreach ($ep in $targets) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($probe).AddParameter('Endpoint', $ep).AddParameter('Timeout', $TimeoutSeconds)
        [pscustomobject]@{ Endpoint = $ep; PS = $ps; Handle = $ps.BeginInvoke() }
    }

    $index = 0
    foreach ($job in $jobs) {
        $index++
        Write-Progress -Activity 'Testing endpoints' -Status $job.Endpoint.Host `
            -PercentComplete (($index / $total) * 100)

        $outcome = $job.PS.EndInvoke($job.Handle)
        $job.PS.Dispose()

        $ep  = $job.Endpoint
        $dns = $outcome.Dns
        $publicDns = $outcome.PublicDns
        $portResults = @($outcome.Ports)
        $tls = $outcome.Tls

        $requiredPorts = @($portResults | Where-Object { -not $_.Advisory })
        $requiredPortsOk = @($requiredPorts | Where-Object { $_.Success }).Count
        $advisoryPortFailures = @($portResults | Where-Object { $_.Advisory -and -not $_.Success })
        $overall =
            if (-not $dns.Success -and $publicDns -and $publicDns.ConfirmedUnavailable) { 'Info' }
            elseif (-not $dns.Success) { 'Fail' }
            elseif ($requiredPortsOk -eq 0) { 'Fail' }
            elseif ($tls -and (-not $tls.Success -or -not $tls.ModernTls)) { 'Fail' }
            elseif ($requiredPortsOk -lt $requiredPorts.Count) { 'Partial' }
            elseif ($advisoryPortFailures.Count -gt 0) { 'Info' }
            else { 'Pass' }

        $results.Add([pscustomobject]@{
            Host      = $ep.Host
            Purpose   = $ep.Purpose
            Category  = $ep.Category
            Platform  = $ep.Platform
            Cloud     = $ep.Cloud
            Dns       = $dns
            PublicDns = $publicDns
            Ports     = $portResults
            Tls       = $tls
            Overall   = $overall
        })

        $color = switch ($overall) { 'Pass' {'Green'} 'Partial' {'Yellow'} 'Info' {'DarkGray'} default {'Red'} }
        Write-Host ("  [{0,-7}] {1}" -f $overall, $ep.Host) -ForegroundColor $color
    }
}
finally {
    $pool.Close()
    $pool.Dispose()
}

Write-Progress -Activity 'Testing endpoints' -Completed

$pass    = @($results | Where-Object Overall -eq 'Pass').Count
$partial = @($results | Where-Object Overall -eq 'Partial').Count
$info    = @($results | Where-Object Overall -eq 'Info').Count
$fail    = @($results | Where-Object Overall -eq 'Fail').Count

$inspDetected  = @($results | Where-Object { $_.Tls -and $_.Tls.Inspection -eq 'Detected' })
$inspSuspected = @($results | Where-Object { $_.Tls -and $_.Tls.Inspection -eq 'Suspected' })

Write-Host ("-" * 60)
Write-Host ("Summary: {0} pass, {1} partial, {2} info, {3} fail" -f $pass, $partial, $info, $fail) -ForegroundColor Cyan
if ($inspDetected.Count -gt 0) {
    Write-Host ("SSL/DPI interception DETECTED on {0} endpoint(s)" -f $inspDetected.Count) -ForegroundColor Red
} elseif ($inspSuspected.Count -gt 0) {
    Write-Host ("SSL/DPI interception SUSPECTED on {0} endpoint(s)" -f $inspSuspected.Count) -ForegroundColor Yellow
} else {
    Write-Host "No SSL/DPI interception detected (certificates issued by public CAs)" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Real-time media relay test (UDP / STUN)
# ---------------------------------------------------------------------------
$mediaResults = New-Object System.Collections.Generic.List[object]
$mediaDns     = $null
$mediaRelayIp = ''

if (-not $SkipMedia) {
    $portLabel = if ($MediaPorts.Count -eq 1) { "$($MediaPorts[0])" } else { "$($MediaPorts[0])-$($MediaPorts[-1])" }
    Write-Host ""
    Write-Host "Real-time media relay test (UDP/STUN)" -ForegroundColor Cyan
    Write-Host "Relay=$MediaRelayHost  Ports=$portLabel" -ForegroundColor DarkGray
    Write-Host ("-" * 60)

    $mediaDns = Test-Dns -HostName $MediaRelayHost
    if ($mediaDns.Success) {
        $mediaRelayIp = ($mediaDns.Addresses -split ',')[0].Trim()
        $mi = 0
        foreach ($mp in $MediaPorts) {
            $mi++
            Write-Progress -Activity 'Testing media ports' -Status "UDP $mp" `
                -PercentComplete (($mi / $MediaPorts.Count) * 100)
            $stun    = Test-StunUdp -HostName $MediaRelayHost -Port $mp -TimeoutMs 2000
            $class =
                if ($mp -eq 3478)                    { 'Primary' }    # STUN-authoritative
                elseif ($mp -ge 3479 -and $mp -le 3481) { 'Secondary' } # media, no STUN reply
                else                                 { 'Extended' }   # not used by relay
            $status =
                if ($stun.Success)       { 'Pass' }
                elseif ($class -eq 'Primary') { 'Fail' }
                else                     { 'Info' }

            $mediaResults.Add([pscustomobject]@{
                Port     = $mp
                Class    = $class
                Success  = $stun.Success
                Detail   = $stun.Detail
                Status   = $status
            })
            $color = switch ($status) { 'Pass' {'Green'} 'Info' {'DarkGray'} default {'Red'} }
            Write-Host ("  [{0,-5}] UDP {1,-5} {2}" -f $status, $mp, $stun.Detail) -ForegroundColor $color
        }
        Write-Progress -Activity 'Testing media ports' -Completed
    }
    else {
        Write-Host "  Relay DNS resolution failed: $($mediaDns.Addresses)" -ForegroundColor Red
    }
}

$mediaReqPass = @($mediaResults | Where-Object { $_.Class -eq 'Primary' -and $_.Success }).Count
$mediaReqFail = @($mediaResults | Where-Object { $_.Class -eq 'Primary' -and -not $_.Success }).Count
$mediaReqTotal = @($mediaResults | Where-Object { $_.Class -eq 'Primary' }).Count

# --- Media quality metrics (latency / jitter / packet loss) -----------------
$mediaQuality = $null
if (-not $SkipMedia -and $mediaDns -and $mediaDns.Success -and $mediaReqPass -gt 0 -and $MediaProbeCount -gt 0) {
    Write-Host ("  Measuring media quality ({0} probes on UDP 3478)..." -f $MediaProbeCount) -ForegroundColor DarkGray
    $mediaQuality = Measure-MediaQuality -HostName $MediaRelayHost -Port 3478 -Count $MediaProbeCount
    Write-Host ("  loss={0}%  latency min/avg/max={1}/{2}/{3} ms  jitter={4} ms" -f `
        $mediaQuality.LossPct, $mediaQuality.MinMs, $mediaQuality.AvgMs, $mediaQuality.MaxMs, $mediaQuality.JitterMs) -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# NTP time sync test
# ---------------------------------------------------------------------------
$ntp = $null
if (-not $SkipNtp) {
    Write-Host ""
    Write-Host "Time sync (NTP)" -ForegroundColor Cyan
    Write-Host ("-" * 60)
    $ntp = Test-Ntp -Server 'time.windows.com'
    $col = if ($ntp.Success) { 'Green' } else { 'Red' }
    Write-Host ("  [{0}] {1} - {2}" -f ($(if($ntp.Success){'Pass'}else{'Fail'}), $ntp.Server, $ntp.Detail)) -ForegroundColor $col
}

# ---------------------------------------------------------------------------
# Proxy configuration detection
# ---------------------------------------------------------------------------
$proxy = $null
if (-not $SkipProxyCheck) {
    Write-Host ""
    Write-Host "Proxy configuration" -ForegroundColor Cyan
    Write-Host ("-" * 60)
    $proxy = Get-ProxyConfig
    if ($proxy.HasProxy) {
        Write-Host "  Proxy configuration DETECTED - media/management traffic should bypass it" -ForegroundColor Yellow
        if ($proxy.WinInetServer) { Write-Host ("  WinINET proxy : {0}" -f $proxy.WinInetServer) -ForegroundColor DarkGray }
        if ($proxy.AutoConfigUrl) { Write-Host ("  PAC / AutoConfig: {0}" -f $proxy.AutoConfigUrl) -ForegroundColor DarkGray }
        if ($proxy.AutoDetect)    { Write-Host "  WPAD auto-detect: enabled" -ForegroundColor DarkGray }
        if ($proxy.WinHttp)       { Write-Host ("  WinHTTP proxy : {0}" -f $proxy.WinHttp) -ForegroundColor DarkGray }
    } else {
        Write-Host "  No system proxy configured (direct access)" -ForegroundColor Green
    }
}

$legacyTls = @($results | Where-Object { $_.Tls -and $_.Tls.Success -and -not $_.Tls.ModernTls })

# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------
function HtmlEncode { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }
Add-Type -AssemblyName System.Web

if (-not $OutputPath) {
    $stamp      = Get-Date -Format 'yyyyMMdd-HHmmss'
    $scriptDir  = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $OutputPath = Join-Path $scriptDir "TeamsRoomsConnectivity-v3.0-$stamp.html"
}

$sourceUrls = @{
    Microsoft365 = 'https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges#skype-for-business-online-and-microsoft-teams'
    Intune        = 'https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints'
    MicrosoftStore = 'https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints#microsoft-store'
    WindowsUpdate = 'https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus#211-connection-from-the-wsus-server-to-the-internet'
    RoomsAndroid  = 'https://learn.microsoft.com/en-us/microsoftteams/rooms/security?tabs=Android#network-security-1'
    RoomsWindows  = 'https://learn.microsoft.com/en-us/microsoftteams/rooms/security?tabs=Windows#network-security-1'
    IoTHubPorts   = 'https://learn.microsoft.com/en-us/azure/iot-hub/iot-hub-devguide-protocols#port-numbers'
}

function Get-SourceLinks {
    param([object]$Result)

    $windowsParent = "<a href='$($sourceUrls.RoomsWindows)' target='_blank' rel='noopener noreferrer'>Teams Rooms Windows security</a>"
    $androidParent = "<a href='$($sourceUrls.RoomsAndroid)' target='_blank' rel='noopener noreferrer'>Teams Android security</a>"
    $separator = "<span class='source-separator'> &gt; </span>"

    $leaf = switch ($Result.Category) {
        'Core Teams' {
            "<a href='$($sourceUrls.Microsoft365)' target='_blank' rel='noopener noreferrer'>Microsoft 365 URLs and IP ranges</a>"
        }
        'Microsoft Store' {
            "<a href='$($sourceUrls.MicrosoftStore)' target='_blank' rel='noopener noreferrer'>Microsoft Store endpoints</a>"
        }
        'Microsoft Intune' {
            "<a href='$($sourceUrls.Intune)' target='_blank' rel='noopener noreferrer'>Microsoft Intune endpoints</a>"
        }
        'Windows Update' {
            "<a href='$($sourceUrls.WindowsUpdate)' target='_blank' rel='noopener noreferrer'>Configure WSUS</a>"
        }
        'Azure IoT Hub' {
            "<a href='$($sourceUrls.IoTHubPorts)' target='_blank' rel='noopener noreferrer'>IoT Hub port numbers</a>"
        }
        default { $null }
    }

    $windowsPath = if ($leaf) { "$windowsParent$separator$leaf" } else { $windowsParent }
    $androidPath = if ($leaf) { "$androidParent$separator$leaf" } else { $androidParent }

    switch ($Result.Platform) {
        'Windows' { $windowsPath }
        'Android' { $androidPath }
        default   { "$windowsPath<br>$androidPath" }
    }
}

function Get-ResultRows {
    param([object[]]$Items)
    $out = foreach ($r in ($Items | Sort-Object Platform, Category, Host)) {
        $badgeClass = switch ($r.Overall) { 'Pass' {'ok'} 'Partial' {'warn'} 'Info' {'info'} default {'bad'} }

        $portCells = foreach ($p in $r.Ports) {
            $cls = if ($p.Success) { 'ok' } elseif ($p.Advisory) { 'info' } else { 'bad' }
            $detail = if ($p.Advisory) { "Advisory port: $($p.Detail)" } else { $p.Detail }
            "<span class='pill $cls' title='$(HtmlEncode $detail)'>$($p.Port)</span>"
        }
        $portsCell = if ($portCells) { $portCells -join ' ' } else { '<span class="muted">-</span>' }

        $tlsCell =
            if ($null -eq $r.Tls) { '<span class="muted">n/a</span>' }
            elseif ($r.Tls.Success -and $r.Tls.ModernTls) { "<span class='pill ok' title='exp $(HtmlEncode $r.Tls.Expiry)'>$(HtmlEncode $r.Tls.Protocol)</span>" }
            elseif ($r.Tls.Success) { "<span class='pill warnpill' title='Legacy TLS - below 1.2, exp $(HtmlEncode $r.Tls.Expiry)'>$(HtmlEncode $r.Tls.Protocol)</span>" }
            else { "<span class='pill bad' title='$(HtmlEncode $r.Tls.Detail)'>Fail</span>" }

        $dnsCell =
            if ($r.Dns.Success) { "<span class='ok-text' title='$(HtmlEncode $r.Dns.Addresses)'>Resolved</span>" }
            elseif ($r.Overall -eq 'Info' -and $r.PublicDns) { "<span class='info-text' title='$(HtmlEncode $r.PublicDns.Detail)'>Unavailable publicly</span>" }
            else { "<span class='bad-text' title='$(HtmlEncode $r.Dns.Addresses)'>Failed</span>" }

        $platClass = switch ($r.Platform) { 'Windows' {'plat-win'} 'Android' {'plat-and'} default {'plat-both'} }

        $sourceLinks = Get-SourceLinks -Result $r

        $inspCell =
            if ($null -eq $r.Tls -or -not $r.Tls.Success) { '<span class="muted">n/a</span>' }
            else {
                switch ($r.Tls.Inspection) {
                    'None'      { "<span class='pill ok' title='$(HtmlEncode $r.Tls.InspectionDetail)'>Clean ($(HtmlEncode $r.Tls.Issuer))</span>" }
                    'Detected'  { "<span class='pill bad' title='$(HtmlEncode $r.Tls.InspectionDetail)'>Intercepted ($(HtmlEncode $r.Tls.Issuer))</span>" }
                    'Suspected' { "<span class='pill warnpill' title='$(HtmlEncode $r.Tls.InspectionDetail)'>Suspected ($(HtmlEncode $r.Tls.Issuer))</span>" }
                    default     { '<span class="muted">unknown</span>' }
                }
            }

@"
<tr class="r-$badgeClass">
  <td><span class="badge $badgeClass">$($r.Overall)</span></td>
  <td><span class="plat $platClass">$(HtmlEncode $r.Platform)</span></td>
  <td class="host">$(HtmlEncode $r.Host)</td>
    <td>$(HtmlEncode $r.Purpose)<div class="source-link">Source: $sourceLinks</div></td>
  <td>$(HtmlEncode $r.Category)</td>
  <td>$(HtmlEncode $r.Cloud)</td>
  <td>$dnsCell</td>
  <td>$portsCell</td>
  <td>$tlsCell</td>
  <td>$inspCell</td>
</tr>
"@
    }
    $out -join "`n"
}

# Single results table (all platforms) with a Platform column.
$resultsRows = Get-ResultRows -Items $results

# Media relay rows.
$mediaRows = foreach ($m in ($mediaResults | Sort-Object Port)) {
    $cls = switch ($m.Status) { 'Pass' {'ok'} 'Info' {'info'} default {'bad'} }
@"
<tr class="r-$cls">
  <td><span class="badge $cls">$($m.Status)</span></td>
  <td class="host">UDP $($m.Port)</td>
  <td>$($m.Class)</td>
  <td>$(HtmlEncode $m.Detail)</td>
</tr>
"@
}
$mediaRowsHtml = if ($mediaRows) { $mediaRows -join "`n" } else { '' }
# Recommended actions built from findings
$actions = New-Object System.Collections.Generic.List[string]
$dnsAdvisories = @($results | Where-Object { $_.Overall -eq 'Info' -and $_.PublicDns })
$portAdvisories = @($results | Where-Object {
    $_.Overall -eq 'Info' -and @($_.Ports | Where-Object { $_.Advisory -and -not $_.Success }).Count -gt 0
})

if ($fail -eq 0 -and $partial -eq 0) {
    if ($info -gt 0) {
        $actions.Add("No customer-network failures were detected for endpoints that could be actively tested.")
    }
    elseif ($inspDetected.Count -eq 0 -and $inspSuspected.Count -eq 0) {
        $actions.Add("All selected endpoints are reachable and no SSL/DPI interception was detected. No action required for the tested scope.")
    } else {
        $actions.Add("All selected endpoints are reachable, but SSL/DPI interception was flagged (see below) - review the SSL Inspection column.")
    }
} else {
    $dnsFails = $results | Where-Object { $_.Overall -eq 'Fail' -and -not $_.Dns.Success }
    if ($dnsFails) {
        $actions.Add("DNS resolution failed for: <b>$(($dnsFails.Host) -join ', ')</b>. Confirm the device can reach your DNS servers and that these hostnames are not blocked by a DNS filter or proxy.")
    }

    $portBlocked = $results | Where-Object {
        $_.Dns.Success -and (@($_.Ports | Where-Object { -not $_.Advisory -and -not $_.Success }).Count -gt 0)
    }
    if ($portBlocked) {
        $blockedList = foreach ($b in $portBlocked) {
            $bp = (@($b.Ports | Where-Object { -not $_.Advisory -and -not $_.Success }).Port) -join ', '
            "$($b.Host) (port $bp)"
        }
        $actions.Add("TCP connection blocked for: <b>$($blockedList -join '; ')</b>. Open the required ports (443 HTTPS/WebSockets, 5671 AMQP, 8883 MQTT) outbound on your firewall for these hosts.")
    }

    $tlsFails = $results | Where-Object { $_.Tls -and -not $_.Tls.Success -and $_.Dns.Success }
    if ($tlsFails) {
        $actions.Add("TLS 1.2 handshake failed for: <b>$(($tlsFails.Host) -join ', ')</b>. This usually means TLS interception/SSL inspection by a proxy or firewall. Teams Rooms devices require TLS 1.2+ and do not support SSL inspection or authenticated proxies for these services - add them to an SSL-bypass / allow list.")
    }

    $actions.Add("Configure Teams real-time media and these management endpoints to <b>bypass proxy servers</b> and SSL inspection. Teams Rooms on Android does not support authenticated proxies or tenant restrictions.")
    $actions.Add("Place Teams Rooms / Android devices on a network segment with direct outbound Internet access (ideally wired), and re-run this test from that segment for an accurate result.")
    if ($partial -gt 0) {
        $actions.Add("<b>Partial</b> results mean at least one required port is open but not all (commonly 443 works but 5671/8883 are blocked). Azure IoT Hub can fall back to 443, but opening 5671/8883 is recommended for resiliency.")
    }
}

if ($dnsAdvisories.Count -gt 0) {
    $advisoryList = foreach ($advisory in $dnsAdvisories) {
        "<b>$(HtmlEncode $advisory.Host)</b> ($(HtmlEncode $advisory.PublicDns.Detail))"
    }
    $actions.Add("Microsoft's live Microsoft 365 endpoint feed still lists these names, but local DNS and both independent public DNS-over-HTTPS resolvers could not resolve them: $($advisoryList -join '; '). They are classified as <b>Info</b>, not as customer firewall failures. Recheck the Microsoft 365 endpoint feed or Microsoft 365 Service health before remediation.")
}

if ($portAdvisories.Count -gt 0) {
    $advisoryList = foreach ($advisory in $portAdvisories) {
        $ports = @($advisory.Ports | Where-Object { $_.Advisory -and -not $_.Success })
        foreach ($port in $ports) {
            "<b>$(HtmlEncode $advisory.Host):$($port.Port)</b> ($(HtmlEncode $port.Detail))"
        }
    }
    $actions.Add("Advisory TCP checks did not connect: $($advisoryList -join '; '). Required HTTPS/TLS connectivity succeeded, so these results are classified as <b>Info</b> and are not counted as customer firewall failures.")
}

if (-not $SkipMedia) {
    if ($mediaDns -and -not $mediaDns.Success) {
        $actions.Add("Media relay <b>$MediaRelayHost</b> could not be resolved by DNS - real-time audio/video may fail. Ensure the Teams media relay FQDN is resolvable.")
    }
    elseif ($mediaReqFail -gt 0) {
        $actions.Add("Real-time <b>media (UDP 3478)</b> to the Teams relay is <b>blocked</b> - the STUN reachability probe got no response. Allow outbound <b>UDP 3478-3481</b> to the Teams media IP ranges <b>52.112.0.0/14</b> and <b>52.122.0.0/15</b>, and let media <b>bypass proxy/SSL inspection</b>. Otherwise calls fall back to TCP 443 with degraded audio/video quality.")
    }
    elseif ($mediaReqPass -gt 0) {
        $actions.Add("Real-time <b>media (UDP 3478)</b> to the Teams relay is <b>reachable</b> (STUN returned a public mapped address) - the optimal UDP media path is available. Note: Microsoft's relay only answers STUN on 3478; 'no response' on 3479-3491 is expected and does not indicate a block. Ensure firewall rules still permit outbound UDP 3478-3481 for actual media flows.")
    }
}

if ($inspDetected.Count -gt 0) {
    $vendorList = ($inspDetected | ForEach-Object { $_.Tls.Issuer } | Sort-Object -Unique) -join ', '
    $actions.Add("<b>SSL inspection / deep packet inspection DETECTED</b> on: <b>$(($inspDetected.Host) -join ', ')</b>. The TLS certificate was re-signed by a proxy CA ($vendorList) instead of Microsoft's public CA. Teams Rooms devices do <b>not support SSL/TLS inspection</b> - add these hosts to an <b>SSL bypass / allow list</b> on your proxy/firewall so traffic is not decrypted.")
}
elseif ($inspSuspected.Count -gt 0) {
    $issuerList = ($inspSuspected | ForEach-Object { $_.Tls.Issuer } | Sort-Object -Unique) -join ', '
    $actions.Add("<b>SSL inspection SUSPECTED</b> on: <b>$(($inspSuspected.Host) -join ', ')</b>. The certificate issuer ($issuerList) is not a recognized public CA used by Microsoft, which often indicates TLS interception. Verify the certificate chain and, if a proxy is decrypting traffic, add these hosts to an SSL bypass list.")
}

if ($legacyTls.Count -gt 0) {
    $actions.Add("<b>Legacy TLS</b> (below 1.2) negotiated on: <b>$(($legacyTls.Host) -join ', ')</b>. Teams devices require <b>TLS 1.2+</b>. Investigate the intermediary forcing an older protocol.")
}

if (-not $SkipNtp -and $ntp) {
    if (-not $ntp.Success) {
        $actions.Add("<b>Time sync (NTP) blocked</b> - could not reach $($ntp.Server) on UDP 123. Accurate time is required for TLS and sign-in; allow outbound UDP 123 to a reliable NTP source.")
    }
    elseif ([math]::Abs([double]$ntp.OffsetSec) -gt 30) {
        $actions.Add("<b>Device clock is off by $($ntp.OffsetSec)s</b> versus NTP. A skew beyond a few minutes breaks Kerberos/OAuth sign-in and TLS validation - correct the system time / time source.")
    }
}

if (-not $SkipProxyCheck -and $proxy -and $proxy.HasProxy) {
    $pd = @()
    if ($proxy.WinInetServer) { $pd += "WinINET: $($proxy.WinInetServer)" }
    if ($proxy.AutoConfigUrl) { $pd += "PAC: $($proxy.AutoConfigUrl)" }
    if ($proxy.AutoDetect)    { $pd += 'WPAD auto-detect enabled' }
    if ($proxy.WinHttp -and $proxy.WinHttp -notmatch 'Direct') { $pd += "WinHTTP: $($proxy.WinHttp)" }
    $actions.Add("<b>A proxy is configured on this PC</b> ($($pd -join '; ')). Teams media should <b>bypass proxies</b>, and Teams Android devices do <b>not support authenticated proxies or tenant restrictions</b>. Ensure Teams/media endpoints and the Management Portal hosts are on the proxy bypass list and not SSL-inspected.")
}

if ($mediaQuality) {
    if ($mediaQuality.LossPct -ge 10) {
        $actions.Add("<b>High media packet loss ($($mediaQuality.LossPct)%)</b> to the Teams relay. Loss above ~1-2% degrades calls; investigate the network path, avoid Wi-Fi, and remove any inline inspection on UDP 3478-3481.")
    }
    elseif ($mediaQuality.JitterMs -ge 30) {
        $actions.Add("<b>High media jitter ($($mediaQuality.JitterMs) ms)</b> to the Teams relay. Jitter above ~30 ms hurts audio/video; prefer a wired connection and apply QoS/DSCP so media is prioritized.")
    }
}

$actionsHtml = ($actions | ForEach-Object { "<li>$_</li>" }) -join "`n"

# Media relay section HTML
$mediaSection = ''
if (-not $SkipMedia) {
    if ($mediaDns -and $mediaDns.Success) {
        $mediaSection = @"
<section>
  <h2>Real-time media relay (UDP / STUN)</h2>
  <p class="legend" style="margin:0 0 10px">
    Probing Teams transport relay <b>$(HtmlEncode $MediaRelayHost)</b>
    ($(HtmlEncode $mediaRelayIp)) with a STUN Binding Request on
    <b>UDP 3478</b> - the relay's STUN-authoritative media port. A <b>Pass</b>
    (public mapped address returned) means the optimal UDP media path works.
    If it fails, allow outbound UDP 3478-3481 to the Teams media IP ranges
    52.112.0.0/14 and 52.122.0.0/15 and let media bypass proxy/SSL inspection.
  </p>
  <table>
    <thead>
      <tr><th>Status</th><th>Port</th><th>Class</th><th>Result</th></tr>
    </thead>
    <tbody>
      $mediaRowsHtml
    </tbody>
  </table>
</section>
"@
    }
    else {
        $reason = if ($mediaDns) { HtmlEncode $mediaDns.Addresses } else { 'not tested' }
        $mediaSection = @"
<section>
  <h2>Real-time media relay (UDP / STUN)</h2>
  <p class="empty bad-text">Could not resolve media relay <b>$(HtmlEncode $MediaRelayHost)</b>: $reason</p>
</section>
"@
    }
}

# Media quality metrics block (appended into the media section)
$mediaQualityHtml = ''
if ($mediaQuality) {
    $lossCls   = if ($mediaQuality.LossPct -ge 10) { 'bad' } elseif ($mediaQuality.LossPct -ge 2) { 'warnpill' } else { 'ok' }
    $jitterCls = if ($mediaQuality.JitterMs -ge 30) { 'bad' } elseif ($mediaQuality.JitterMs -ge 15) { 'warnpill' } else { 'ok' }
    $latCls    = if ($mediaQuality.AvgMs -ge 100) { 'bad' } elseif ($mediaQuality.AvgMs -ge 50) { 'warnpill' } else { 'ok' }
    $mediaQualityHtml = @"
<h3 style="font-size:14px;margin:16px 0 8px">Media quality (UDP 3478, $($mediaQuality.Sent) probes)</h3>
<table>
  <thead><tr><th>Packet loss</th><th>Latency avg</th><th>Latency min/max</th><th>Jitter</th></tr></thead>
  <tbody><tr>
    <td><span class="pill $lossCls">$($mediaQuality.LossPct)%</span></td>
    <td><span class="pill $latCls">$($mediaQuality.AvgMs) ms</span></td>
    <td>$($mediaQuality.MinMs) / $($mediaQuality.MaxMs) ms</td>
    <td><span class="pill $jitterCls">$($mediaQuality.JitterMs) ms</span></td>
  </tr></tbody>
</table>
<p class="legend" style="margin-top:8px">Targets for good calls: packet loss &lt; 1-2%, jitter &lt; 30 ms, latency &lt; 100 ms one-way.</p>
"@
    # Inject quality table just before the closing </section> of the media block.
    $mediaSection = $mediaSection -replace '</section>\s*$', "$mediaQualityHtml`n</section>"
}

# System checks section (NTP + proxy)
$systemSection = ''
$sysRows = New-Object System.Collections.Generic.List[string]
if (-not $SkipNtp -and $ntp) {
    if ($ntp.Success) {
        $offAbs = [math]::Abs([double]$ntp.OffsetSec)
        $ntpCls = if ($offAbs -gt 30) { 'bad' } elseif ($offAbs -gt 5) { 'warnpill' } else { 'ok' }
        $sysRows.Add("<tr><td class='host'>Time sync (NTP)</td><td>$(HtmlEncode $ntp.Server) : UDP 123</td><td><span class='pill $ntpCls'>offset $($ntp.OffsetSec)s</span></td></tr>")
    } else {
        $sysRows.Add("<tr class='r-bad'><td class='host'>Time sync (NTP)</td><td>$(HtmlEncode $ntp.Server) : UDP 123</td><td><span class='pill bad'>$(HtmlEncode $ntp.Detail)</span></td></tr>")
    }
}
if (-not $SkipProxyCheck -and $proxy) {
    if ($proxy.HasProxy) {
        $pdetail = @()
        if ($proxy.WinInetServer) { $pdetail += "WinINET $($proxy.WinInetServer)" }
        if ($proxy.AutoConfigUrl) { $pdetail += "PAC $($proxy.AutoConfigUrl)" }
        if ($proxy.AutoDetect)    { $pdetail += 'WPAD auto-detect' }
        if ($proxy.WinHttp -and $proxy.WinHttp -notmatch 'Direct') { $pdetail += "WinHTTP $($proxy.WinHttp)" }
        $sysRows.Add("<tr class='r-warn'><td class='host'>Proxy configuration</td><td>$(HtmlEncode ($pdetail -join '; '))</td><td><span class='pill warnpill'>Proxy set - ensure bypass</span></td></tr>")
    } else {
        $sysRows.Add("<tr><td class='host'>Proxy configuration</td><td>Direct access</td><td><span class='pill ok'>No proxy</span></td></tr>")
    }
}
if ($sysRows.Count -gt 0) {
    $systemSection = @"
<section>
  <h2>System checks (time sync &amp; proxy)</h2>
  <table>
    <thead><tr><th>Check</th><th>Detail</th><th>Result</th></tr></thead>
    <tbody>
      $($sysRows -join "`n")
    </tbody>
  </table>
  <p class="legend" style="margin-top:8px">Accurate time (NTP) is required for TLS/sign-in. A configured proxy must be bypassed for Teams media and Management Portal endpoints; Teams Android devices don't support authenticated proxies or tenant restrictions.</p>
</section>
"@
}


$hostName = $env:COMPUTERNAME
$userName = $env:USERNAME
$generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Teams Rooms Connectivity Report</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; background:#f3f3f6; color:#1b1b1f; }
  header { background: linear-gradient(120deg,#5059c9,#7b83eb); color:#fff; padding:28px 32px; }
  header h1 { margin:0 0 4px; font-size:22px; }
  header .meta { opacity:.9; font-size:13px; }
  main { padding: 24px 32px 60px; max-width:1200px; margin:0 auto; }
  .cards { display:flex; gap:16px; flex-wrap:wrap; margin:20px 0 28px; }
  .card { flex:1 1 140px; background:#fff; border-radius:12px; padding:18px 20px; box-shadow:0 1px 3px rgba(0,0,0,.08); }
  .card .n { font-size:30px; font-weight:700; }
  .card.pass .n { color:#107c10; } .card.partial .n { color:#c19c00; }
    .card.info .n { color:#605e5c; } .card.fail .n { color:#c50f1f; } .card.total .n { color:#5059c9; }
  .card.media .n { color:#0f7b7b; }
  .card.insp .n { color:#8a6d00; }
  .card .l { font-size:12px; text-transform:uppercase; letter-spacing:.06em; color:#666; }
  section h2 { font-size:16px; margin:26px 0 10px; }
  table { width:100%; border-collapse:collapse; background:#fff; border-radius:12px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.08); }
  th, td { text-align:left; padding:10px 12px; font-size:13px; border-bottom:1px solid #ececf0; }
  th { background:#fafafc; text-transform:uppercase; font-size:11px; letter-spacing:.05em; color:#555; }
  tr:last-child td { border-bottom:none; }
  .host { font-family: Consolas, monospace; font-weight:600; }
  .badge { padding:2px 9px; border-radius:20px; font-size:11px; font-weight:700; color:#fff; }
  .badge.ok{background:#107c10;} .badge.warn{background:#c19c00;} .badge.bad{background:#c50f1f;} .badge.info{background:#8a8886;}
  .plat { display:inline-block; padding:2px 8px; border-radius:6px; font-size:11px; font-weight:700; }
  .plat-win { background:#e5e7fb; color:#3b41a8; }
  .plat-and { background:#dff3e6; color:#1f7a44; }
  .plat-both { background:#efe6f8; color:#6b3fa0; }
  .pill { display:inline-block; padding:1px 7px; border-radius:6px; font-size:11px; font-weight:600; margin:1px; }
    .pill.ok{background:#dff6dd;color:#0b6a0b;} .pill.info{background:#edebe9;color:#605e5c;} .pill.bad{background:#fde7e9;color:#a4262c;}
  .pill.warnpill{background:#fff4ce;color:#8a6d00;}
    .ok-text{color:#107c10;font-weight:600;} .info-text{color:#605e5c;font-weight:600;} .bad-text{color:#c50f1f;font-weight:600;}
  .muted{color:#999;}
    .source-link { margin-top:4px; font-size:11px; color:#666; }
    .source-link a { color:#3b41a8; text-decoration:underline; text-underline-offset:2px; }
    .source-separator { color:#999; }
  tr.r-bad td { background:#fff6f7; } tr.r-warn td { background:#fffdf3; } tr.r-info td { color:#777; }
  .actions { background:#fff; border-radius:12px; padding:6px 26px; box-shadow:0 1px 3px rgba(0,0,0,.08); }
  .actions li { margin:12px 0; line-height:1.5; font-size:14px; }
  footer { text-align:center; color:#888; font-size:12px; padding:20px; }
  .legend { font-size:12px; color:#666; margin-top:8px; }
  .columns { display:flex; gap:22px; flex-wrap:wrap; align-items:flex-start; }
  .col { flex:1 1 460px; min-width:0; }
  .col-title { display:flex; align-items:center; gap:8px; font-size:15px; margin:0 0 10px;
               padding-bottom:6px; border-bottom:3px solid #5059c9; }
  .col-title .dot { width:11px; height:11px; border-radius:50%; display:inline-block; }
  .col-title .cnt { background:#eee; color:#444; border-radius:20px; padding:1px 9px; font-size:12px; font-weight:700; }
  .col-title .mini { font-size:11px; font-weight:700; padding:1px 7px; border-radius:20px; }
  .mini.ok{background:#dff6dd;color:#0b6a0b;} .mini.warn{background:#fff4ce;color:#8a6d00;} .mini.bad{background:#fde7e9;color:#a4262c;}
  .col table { font-size:12px; }
  .col th, .col td { padding:8px 9px; }
  .empty { padding:14px; background:#fff; border-radius:12px; box-shadow:0 1px 3px rgba(0,0,0,.08); }
  @media (max-width: 980px) { .col { flex:1 1 100%; } }
</style>
</head>
<body>
<header>
  <h1>Microsoft Teams Rooms - Endpoint Connectivity Report</h1>
  <div class="meta">
    Generated $generated &middot; Host <b>$(HtmlEncode $hostName)</b> &middot; User <b>$(HtmlEncode $userName)</b><br>
    Scope: Platform = <b>Both</b> &middot; Cloud = <b>Commercial/Worldwide only</b> &middot; Timeout = ${TimeoutSeconds}s &middot; Script v$ScriptVersion<br>
    Out of scope: <b>GCC, GCC High, DoD, 21Vianet/China, and other government or sovereign clouds</b>
  </div>
</header>
<main>
  <div class="cards">
    <div class="card total"><div class="n">$total</div><div class="l">Endpoints</div></div>
    <div class="card pass"><div class="n">$pass</div><div class="l">Pass</div></div>
    <div class="card partial"><div class="n">$partial</div><div class="l">Partial</div></div>
    <div class="card info"><div class="n">$info</div><div class="l">Info</div></div>
    <div class="card fail"><div class="n">$fail</div><div class="l">Fail</div></div>
    <div class="card media"><div class="n">$mediaReqPass/$mediaReqTotal</div><div class="l">Media UDP 3478</div></div>
    <div class="card insp"><div class="n">$($inspDetected.Count)</div><div class="l">SSL Intercept</div></div>
  </div>

  <section>
    <h2>Recommended actions</h2>
    <ul class="actions">
      $actionsHtml
    </ul>
  </section>

  <section>
    <h2>Detailed results</h2>
    <table>
      <thead>
        <tr>
          <th>Status</th><th>Platform</th><th>Endpoint</th><th>Purpose</th><th>Category</th>
          <th>Cloud</th><th>DNS</th><th>Ports</th><th>TLS</th><th>SSL Inspection</th>
        </tr>
      </thead>
      <tbody>
        $resultsRows
      </tbody>
    </table>
    <p class="legend">
      Platform: <span class="plat plat-win">Windows</span> <span class="plat plat-and">Android</span>
      <span class="plat plat-both">Both</span> (applies to either device family).
      Ports: <b>443</b> HTTPS / MQTT+AMQP over WebSockets &middot;
      <b>5671</b> AMQP &middot; <b>8883</b> MQTT (Azure IoT Hub).
      <b>SSL Inspection</b>: the CA that signed each endpoint's certificate -
      <span class="pill ok">Clean</span> = Microsoft/public CA,
      <span class="pill warnpill">Suspected</span> / <span class="pill bad">Intercepted</span>
      = a proxy re-signed the certificate (unsupported by Teams devices).
            <b>Info</b> means a Microsoft-published endpoint failed local and public DNS,
            or an advisory port failed while required HTTPS/TLS succeeded; it is not counted
            as a customer firewall failure.
            Hover any pill for details. TLS 1.2 is required by Teams devices.
    </p>
  </section>

  $mediaSection

  $systemSection
</main>
<footer>
  Read-only network test - no configuration was changed on this PC.
  Endpoints per Microsoft Teams Rooms Pro Management Portal requirements.
    &middot; Test-TeamsRoomsEndpoints-v3.0.ps1 v$ScriptVersion
</footer>
</body>
</html>
"@

$html | Out-File -FilePath $OutputPath -Encoding utf8
Write-Host "Report written to: $OutputPath" -ForegroundColor Green

if (-not $NoBrowser) {
    try { Start-Process $OutputPath } catch { Write-Warning "Could not auto-open report: $($_.Exception.Message)" }
}

# Return summary object for pipeline use
[pscustomobject]@{
    Total          = $total
    Pass           = $pass
    Partial        = $partial
    Info           = $info
    Fail           = $fail
    MediaReqPass   = $mediaReqPass
    MediaReqFail   = $mediaReqFail
    MediaLossPct   = if ($mediaQuality) { $mediaQuality.LossPct } else { $null }
    MediaJitterMs  = if ($mediaQuality) { $mediaQuality.JitterMs } else { $null }
    MediaAvgMs     = if ($mediaQuality) { $mediaQuality.AvgMs } else { $null }
    SslIntercepted = $inspDetected.Count
    SslSuspected   = $inspSuspected.Count
    LegacyTls      = $legacyTls.Count
    NtpOffsetSec   = if ($ntp -and $ntp.Success) { $ntp.OffsetSec } else { $null }
    ProxyConfigured = if ($proxy) { $proxy.HasProxy } else { $null }
    ReportPath     = $OutputPath
}
