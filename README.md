# Teams Rooms Endpoint Connectivity Tester v3.0

Tests whether **this PC** can reach the mandatory Microsoft Teams / Teams Rooms
endpoints - core Teams client sign-in, Microsoft Store (AppInstallManager),
telemetry, the Teams Rooms Pro Management Portal (Azure IoT Hub, Web PubSub,
agent) and Microsoft Intune - and produces an HTML report with recommended
actions.

> Runs entirely in the current user context. **No administrator rights are
> required.** Nothing is installed and no machine settings are changed - it only
> opens outbound test connections. Endpoints are probed **in parallel** (see
> `-MaxParallel`) so the test finishes quickly even when several endpoints are
> blocked and time out.
>
> Always tests **both platforms** (Windows + Android), the **core Teams /
> Microsoft 365 sign-in endpoints**, and the documented **Commercial/Worldwide
> cloud only** - just run it.
>
> **Out of scope:** GCC, GCC High, DoD, Microsoft 365 operated by 21Vianet in
> China, and other government or sovereign clouds. Their endpoints are not
> tested or included in the report.

## How to run

**Easiest** - double-click `Run-ConnectivityTest-v3.0.cmd`.

**Or** from PowerShell:

```powershell
.\Test-TeamsRoomsEndpoints-v3.0.ps1
```

If PowerShell blocks the script, launch it without changing machine policy:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Test-TeamsRoomsEndpoints-v3.0.ps1
```

## Endpoints tested

The **Purpose** column in the HTML report shows each source from high to low:
the applicable Teams Rooms platform guidance first, followed by the specific
page referenced by that guidance. For example:

[Teams Rooms on Windows network security](https://learn.microsoft.com/en-us/microsoftteams/rooms/security?tabs=Windows#network-security-1)
&gt; [Configure WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus#211-connection-from-the-wsus-server-to-the-internet)

**Microsoft Teams Rooms on Windows (MTRoW) sources**

- Microsoft Teams, Exchange Online, SharePoint, Microsoft 365 Common, and
  Office Online: [Microsoft Teams Rooms on Windows and Teams Android device security - Microsoft Teams | Microsoft Learn](https://learn.microsoft.com/en-us/microsoftteams/rooms/security?tabs=Windows#network-security-1)
  &gt; [Microsoft 365 URLs and IP address ranges](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges#skype-for-business-online-and-microsoft-teams)
- Windows Update: [Microsoft Teams Rooms on Windows and Teams Android device security - Microsoft Teams | Microsoft Learn](https://learn.microsoft.com/en-us/microsoftteams/rooms/security?tabs=Windows#network-security-1)
  &gt; [Configure WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus#211-connection-from-the-wsus-server-to-the-internet)
- Microsoft Store: [Microsoft Teams Rooms on Windows and Teams Android device security - Microsoft Teams | Microsoft Learn](https://learn.microsoft.com/en-us/microsoftteams/rooms/security?tabs=Windows#network-security-1)
  &gt; [Microsoft Store endpoints](https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints#microsoft-store)
- Microsoft Intune: [Microsoft Teams Rooms on Windows and Teams Android device security - Microsoft Teams | Microsoft Learn](https://learn.microsoft.com/en-us/microsoftteams/rooms/security?tabs=Windows#network-security-1)
  &gt; [Network endpoints for Microsoft Intune](https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints)
- Telemetry and Teams Rooms Pro Management Portal URLs:
  [Microsoft Teams Rooms on Windows and Teams Android device security - Microsoft Teams | Microsoft Learn](https://learn.microsoft.com/en-us/microsoftteams/rooms/security?tabs=Windows#network-security-1)
- Azure IoT Hub firewall ports: [Microsoft Teams Rooms on Windows and Teams Android device security - Microsoft Teams | Microsoft Learn](https://learn.microsoft.com/en-us/microsoftteams/rooms/security?tabs=Windows#network-security-1)
  &gt; [Azure IoT Hub communication protocols and port numbers](https://learn.microsoft.com/en-us/azure/iot-hub/iot-hub-devguide-protocols#port-numbers)

**Teams Android device sources**

- Microsoft Teams, Exchange Online, SharePoint, Microsoft 365 Common, and
  Office Online: [Microsoft Teams Rooms on Windows and Teams Android device security - Microsoft Teams | Microsoft Learn](https://learn.microsoft.com/en-us/microsoftteams/rooms/security?tabs=Android#network-security-1)
  &gt; [Microsoft 365 URLs and IP address ranges](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges#skype-for-business-online-and-microsoft-teams)
- Microsoft Intune: [Microsoft Teams Rooms on Windows and Teams Android device security - Microsoft Teams | Microsoft Learn](https://learn.microsoft.com/en-us/microsoftteams/rooms/security?tabs=Android#network-security-1)
  &gt; [Network endpoints for Microsoft Intune](https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints)
- Teams Rooms Pro Management Portal URLs, including the NOAM, EMEA, and APAC
  conference bar, touch console, phone, and panel IoT hubs:
  [Microsoft Teams Rooms on Windows and Teams Android device security - Microsoft Teams | Microsoft Learn](https://learn.microsoft.com/en-us/microsoftteams/rooms/security?tabs=Android#network-security-1)
- Azure IoT Hub firewall ports: [Microsoft Teams Rooms on Windows and Teams Android device security - Microsoft Teams | Microsoft Learn](https://learn.microsoft.com/en-us/microsoftteams/rooms/security?tabs=Android#network-security-1)
  &gt; [Azure IoT Hub communication protocols and port numbers](https://learn.microsoft.com/en-us/azure/iot-hub/iot-hub-devguide-protocols#port-numbers)

**Core Teams / Microsoft 365** (always tested, applies to both platforms)
- Sign-in: `login.microsoftonline.com`, `login.microsoft.com`,
  `device.login.microsoftonline.com`, `accounts.accesscontrol.windows.net`
- Client / API: `graph.microsoft.com`, `teams.microsoft.com`,
  `teams.cloud.microsoft`
- Content delivery: `aka.ms`, `join.secure.skypeassets.com`,
  `mlccdnprod.azureedge.net`. The latter two remain in Microsoft's live
  Microsoft 365 endpoint feed. If local DNS fails for either name, the script
  also checks Google and Cloudflare DNS-over-HTTPS so a Microsoft-side DNS
  publication problem is not misreported as a customer firewall failure.

**Known informational results**

The following endpoints previously appeared as **Fail** in the report even
though they were not blocked:

- `join.secure.skypeassets.com`
- `mlccdnprod.azureedge.net`
- `licensing.mp.microsoft.com` on TCP port 80

These results are now classified as **Info**. Required connectivity failures,
including HTTPS/TLS failures on `licensing.mp.microsoft.com` port 443, are still
classified as **Fail**.

**Windows**
- Windows Update representative concrete hosts (TCP 80/443):
  `windowsupdate.microsoft.com`, `download.windowsupdate.com`,
  `download.microsoft.com`, `ntservicepack.microsoft.com`, `go.microsoft.com`, and
  `dl.delivery.mp.microsoft.com`. Microsoft also requires wildcard domains
  listed in the linked WSUS guidance; wildcard names cannot be directly probed.
  `wustat.windows.com` is not tested: it is documented for traffic from a WSUS
  server to the Internet, is not a direct Teams Rooms client health endpoint,
  and currently has no public DNS record.
- Microsoft Store API / AppInstallManager (TCP 80 & 443): `displaycatalog.mp.microsoft.com`,
  `purchase.md.mp.microsoft.com`, `licensing.mp.microsoft.com`, `storeedgefd.dsx.mp.microsoft.com`.
  For `licensing.mp.microsoft.com`, HTTPS/TLS on 443 remains required, while
  TCP 80 is an advisory check: a port 80 failure is reported as **Info**, not
  **Partial** or **Fail**, when 443 and TLS succeed.
- Telemetry: `vortex.data.microsoft.com`, `settings.data.microsoft.com`
- Management Portal: `agent.rooms.microsoft.com`, the `mmr*iot.azure-devices.net`
  IoT hubs and `mmr*pubsub.webpubsub.azure.com` Web PubSub hubs
- Microsoft Intune: `manage.microsoft.com`

**Android**
- Management Portal IoT hubs per device class/region (`*cbiot`, `*tciot`,
  `*phonesiot`, `*panelsiot` for NOAM/EMEA/APAC)
- Microsoft Intune: `manage.microsoft.com`

**Cloud scope**

Only Commercial/Worldwide endpoints are included. GCC, GCC High, DoD,
21Vianet/China, and other government or sovereign-cloud endpoints are
intentionally excluded from this test.

## Parameters

| Parameter           | Values                                             | Default      |
|---------------------|----------------------------------------------------|--------------|
| `-TimeoutSeconds`   | per-connection timeout                             | `5`          |
| `-OutputPath`       | path for the HTML report                           | auto         |
| `-NoBrowser`        | switch - don't auto-open the report                | off          |
| `-SkipMedia`        | switch - skip the UDP/STUN media relay test        | off          |
| `-MediaRelayHost`   | Teams transport relay FQDN to probe                | `worldaz.tr.teams.microsoft.com` |
| `-MediaPorts`       | UDP ports to probe for media                       | `3478`       |
| `-MediaProbeCount`  | STUN probes for latency/jitter/loss (0 = skip)     | `20`         |
| `-SkipNtp`          | switch - skip the NTP time-sync check              | off          |
| `-SkipProxyCheck`   | switch - skip system/PAC proxy detection           | off          |
| `-MaxParallel`      | max endpoints tested concurrently                  | `12`         |

## What it checks per endpoint

1. **DNS resolution** - can the hostname be resolved. If local DNS cannot
  resolve `join.secure.skypeassets.com` or `mlccdnprod.azureedge.net`, the
  script queries both Google and Cloudflare DNS-over-HTTPS. A DNS error from
  both public resolvers produces **Info** rather than **Fail**. If either name
  resolves publicly, or both public checks cannot be completed, the local DNS
  failure remains **Fail** so local filtering is not hidden.
2. **TCP connectivity** on the relevant ports:
   - `443`  HTTPS / MQTT+AMQP over WebSockets
   - `5671` AMQP (Azure IoT Hub)
   - `8883` MQTT (Azure IoT Hub)
  - `80`   HTTP (Microsoft Store AppInstallManager / Windows Update). Port 80
    is advisory only for `licensing.mp.microsoft.com`; required-port behavior
    is unchanged for every other endpoint.
3. **TLS handshake** on 443 - negotiates the highest protocol allowed by the
  operating system and **fails the endpoint for legacy TLS** below 1.2 (Teams
  devices require TLS 1.2+).
4. **SSL / deep-packet-inspection detection** - inspects the certificate chain.
   If the cert was re-signed by a proxy CA (Zscaler, Netskope, Palo Alto,
   Fortinet, Blue Coat, etc.) instead of a Microsoft/public CA, the endpoint is
   flagged **Intercepted** (or **Suspected** for an unrecognized issuer).

Each result row is tagged with the device **Platform** (`Windows`, `Android`,
or `Both`).

Result meanings:

- **Pass** - DNS, all required TCP ports, TLS 1.2+, and any configured advisory
  port checks succeeded.
- **Partial** - the endpoint resolved and at least one, but not all, required
  ports connected. Advisory-port failures do not produce **Partial**.
- **Info** - either a hostname still published by Microsoft failed local DNS
  and both independent public DNS checks, or an advisory port failed while all
  required connectivity succeeded. This is not counted as a customer-network
  failure.
- **Fail** - local DNS, all required ports, or required TLS validation failed.

The two fallback checks use HTTPS to `dns.google` and
`cloudflare-dns.com` only when one of the two monitored CDN names fails local
DNS. No public fallback is used for other endpoints. The licensing port 80
advisory does not use public DNS fallback because its hostname already resolved;
it only changes how that individual TCP result is classified.

## System checks (always on unless skipped)

- **NTP time sync** – queries `time.windows.com` (UDP 123) and reports the
  device clock offset. Large skew breaks TLS and sign-in.
- **Proxy detection** – reads WinINET/WinHTTP/PAC/WPAD settings and warns if a
  proxy is configured (Teams media must bypass proxies; Android devices don't
  support authenticated proxies or tenant restrictions).

## Real-time media test (UDP / STUN)

The script probes the Microsoft Teams transport relay with STUN Binding
Requests over **UDP 3478** (the relay's STUN-authoritative media port). A **Pass**
returns your public mapped address and proves the optimal UDP media path works.
It then sends repeated probes to measure **latency, jitter and packet loss**.

If UDP 3478 is blocked, allow outbound **UDP 3478–3481** to the Teams media IP
ranges **52.112.0.0/14** and **52.122.0.0/15**, and let media bypass proxy/SSL
inspection. Otherwise calls fall back to TCP 443 with degraded quality.

## Output

A self-contained HTML report `TeamsRoomsConnectivity-v3.0-<timestamp>.html` is
written next to the script and opened in your default browser. It contains a summary,
a per-endpoint results table, tailored remediation guidance, and clickable Microsoft
Learn source links in the **Purpose** column for each endpoint.

Run the test **from the same network segment** where the Teams Rooms / Android
device lives for an accurate result.
