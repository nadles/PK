#Requires -Version 5.1
<#
.SYNOPSIS
    Entra ID & Intune Connectivity Checker - Full Endpoint Coverage

.DESCRIPTION
    Tests Microsoft-documented endpoints required for:
    - Entra Hybrid Join
    - Intune MDM Enrollment & Management

    Compatible with Windows PowerShell 5.1 and PowerShell 7.x.

.PARAMETER ExportCSV
    Export test results to CSV on Desktop.

.PARAMETER ExportSummaryTable
    Export network requirements summary to CSV on Desktop.

.PARAMETER Region
    Tenant region for region-specific endpoints.
    Allowed values: Global (default), AsiaPacific

.EXAMPLE
    .\Test-EntraIntuneConnectivity.ps1

.EXAMPLE
    .\Test-EntraIntuneConnectivity.ps1 -ExportCSV

.EXAMPLE
    .\Test-EntraIntuneConnectivity.ps1 -Region AsiaPacific -ExportCSV

.EXAMPLE
    .\Test-EntraIntuneConnectivity.ps1 -ExportSummaryTable

.EXAMPLE
    .\Test-EntraIntuneConnectivity.ps1 -ExportCSV -ExportSummaryTable

.NOTES
    Version : 2.1 | 2026-03-24
    Author  : PIWI 2026
#>

[CmdletBinding()]
param(
    [switch]$ExportCSV,
    [switch]$ExportSummaryTable,
    [ValidateSet("Global", "AsiaPacific")]
    [string]$Region = "Global",
    [string]$CSVPath = "$env:USERPROFILE\Desktop\ConnectivityCheck_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [string]$SummaryCSVPath = "$env:USERPROFILE\Desktop\NetworkRequirements_Summary_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ErrorActionPreference = 'SilentlyContinue'

# Check if running as administrator
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

# Store user context for reports
$RunByUser = "$env:USERDOMAIN\$env:USERNAME"

# ----------------------------------------------------------------------
# ENDPOINT DEFINITIONS
# Sources:
#   [1] Entra Hybrid Join prerequisites
#   [2] Intune endpoints
# ----------------------------------------------------------------------

$Endpoints = [System.Collections.ArrayList]::new()

function Get-EndpointRegion {
    param([string]$URL)

    if ($URL -match "imeswda|macsidecar\.manage|intunemaape[1-6]\.(eus|cus|wus|scus|ncus)") {
        return "North America"
    }
    elseif ($URL -match "imeswdb|macsidecareu|intunemaape(7|8|9|10|11|12)\.(neu|weu)") {
        return "Europe"
    }
    elseif ($URL -match "imeswdc|macsidecarap|intunemaape(13|17|18|19)\.jpe") {
        return "Asia Pacific"
    }
    else {
        return "Global"
    }
}

function Add-EP {
    param(
        [string]$Cat,
        [string]$Name,
        [string]$URL,
        [int]$Port = 443,
        [bool]$Critical = $false,
        [string]$Ref = "",
        [string]$Note = "",
        [bool]$NoSSLInspection = $false
    )

    [void]$script:Endpoints.Add([PSCustomObject]@{
        Category        = $Cat
        Name            = $Name
        URL             = $URL
        Port            = $Port
        Critical        = $Critical
        Ref             = $Ref
        Note            = $Note
        NoSSLInspection = $NoSSLInspection
        GeoRegion       = $(Get-EndpointRegion -URL $URL)
    })
}

# ----------------------------------------------------------------------
# ENTRA ID / HYBRID JOIN [Ref 1]
# ----------------------------------------------------------------------
Add-EP "Entra ID - Hybrid Join" "Login / Authentication"          "login.microsoftonline.com"                   443 $true  "[1] Required" "" $true
Add-EP "Entra ID - Hybrid Join" "Login (Microsoft)"               "login.microsoft.com"                         443 $true  "[MS] Required" "" $true
Add-EP "Entra ID - Hybrid Join" "Device Registration"             "enterpriseregistration.windows.net"          443 $true  "[1] Required" "" $true
Add-EP "Entra ID - Hybrid Join" "Device Registration (Microsoft)" "enterpriseregistration.microsoft.com"        443 $true  "[MS] Required" "" $true
Add-EP "Entra ID - Hybrid Join" "Device Registration (cert auth)" "certauth.enterpriseregistration.windows.net" 443 $true  "[2] ID:59" "" $true
Add-EP "Entra ID - Hybrid Join" "Device Login"                    "device.login.microsoftonline.com"            443 $true  "[1] Required" "Exclude from TLS break-and-inspect" $true
Add-EP "Entra ID - Hybrid Join" "Seamless SSO / Autologon"        "autologon.microsoftazuread-sso.com"          443 $false "[1] If using SSO"

# ----------------------------------------------------------------------
# ENTRA ID / AUTHENTICATION [Ref 2 ID:56]
# ----------------------------------------------------------------------
Add-EP "Entra ID - Auth" "Login (HTTP redirect)"       "login.microsoftonline.com" 80  $false "[2] ID:56" "" $true
Add-EP "Entra ID - Auth" "Login (legacy)"              "login.windows.net"         443 $false "[2] ID:56"
Add-EP "Entra ID - Auth" "Graph API"                   "graph.microsoft.com"       443 $true  "[2] ID:56"
Add-EP "Entra ID - Auth" "Graph API (legacy)"          "graph.windows.net"         443 $false "[2] ID:56"
Add-EP "Entra ID - Auth" "Azure DRS"                   "drs.windows.net"           443 $true  "[1][2]"
Add-EP "Entra ID - Auth" "STS / Token Service"         "sts.windows.net"           443 $true  "[1][2]"
Add-EP "Entra ID - Auth" "STS / Token Service (MSFT)"  "msft.sts.microsoft.com"    443 $true  "[MS] Required" "Certificate enrollment" $true
Add-EP "Entra ID - Auth" "Auth CDN (msftauth)"         "aadcdn.msftauth.net"       443 $false "[2] ID:181" "" $true
Add-EP "Entra ID - Auth" "Auth CDN (msauth)"           "aadcdn.msauth.net"         443 $false "[2] ID:181" "" $true
Add-EP "Entra ID - Auth" "Auth CDN (alcdn)"            "alcdn.msauth.net"          443 $false "[2] ID:181"
Add-EP "Entra ID - Auth" "MS Account (Live)"           "account.live.com"          443 $false "[2] ID:97"
Add-EP "Entra ID - Auth" "MS Account Login (Live)"     "login.live.com"            443 $false "[2] ID:97"

# ----------------------------------------------------------------------
# INTUNE CORE SERVICE [Ref 2 ID:163]
# ----------------------------------------------------------------------
Add-EP "Intune - Core" "MDM Enrollment"                 "enrollment.manage.microsoft.com"               443 $true  "[2] ID:163" "" $true
Add-EP "Intune - Core" "Enterprise Enrollment"          "enterpriseenrollment.manage.microsoft.com"     443 $true  "[2] ID:163" "" $true
Add-EP "Intune - Core" "Enterprise Enrollment (-s alt)" "enterpriseenrollment-s.manage.microsoft.com"   443 $true  "[2] ID:163" "" $true
Add-EP "Intune - Core" "Management Service"             "manage.microsoft.com"                          443 $true  "[2] ID:163" "Requires unauthenticated proxy access" $true
Add-EP "Intune - Core" "Device Management (DM)"         "dm.microsoft.com"                              443 $true  "[2] MDE/EPM" "SSL inspection NOT supported" $true
Add-EP "Intune - Core" "Portal"                         "portal.manage.microsoft.com"                   443 $false "[2] ID:163"
Add-EP "Intune - Core" "Compliance"                     "compliance.manage.microsoft.com"               443 $false "[2]"
Add-EP "Intune - Core" "Diagnostics"                    "diagnostics.manage.microsoft.com"              443 $false "[2]"
Add-EP "Intune - Core" "Config Service"                 "config.manage.microsoft.com"                   443 $false "[2]"
Add-EP "Intune - Core" "Fef Service (sample NA)"        "fef.msuc06.manage.microsoft.com"               443 $false "[2]"

# ----------------------------------------------------------------------
# INTUNE - WIN32 APPS CDN [Ref 2 ID:170]
# ----------------------------------------------------------------------
Add-EP "Intune - Win32 Apps" "Win32 CDN (swda01)"  "swda01-mscdn.manage.microsoft.com" 443 $false "[2] ID:170"
Add-EP "Intune - Win32 Apps" "Win32 CDN (swda02)"  "swda02-mscdn.manage.microsoft.com" 443 $false "[2] ID:170"
Add-EP "Intune - Win32 Apps" "Win32 CDN (swdb01)"  "swdb01-mscdn.manage.microsoft.com" 443 $false "[2] ID:170"
Add-EP "Intune - Win32 Apps" "Win32 CDN (swdb02)"  "swdb02-mscdn.manage.microsoft.com" 443 $false "[2] ID:170"
Add-EP "Intune - Win32 Apps" "Win32 CDN (swdc01)"  "swdc01-mscdn.manage.microsoft.com" 443 $false "[2] ID:170"
Add-EP "Intune - Win32 Apps" "Win32 CDN (swdc02)"  "swdc02-mscdn.manage.microsoft.com" 443 $false "[2] ID:170"
Add-EP "Intune - Win32 Apps" "Win32 CDN (swdd01)"  "swdd01-mscdn.manage.microsoft.com" 443 $false "[2] ID:170"
Add-EP "Intune - Win32 Apps" "Win32 CDN (swdd02)"  "swdd02-mscdn.manage.microsoft.com" 443 $false "[2] ID:170"
Add-EP "Intune - Win32 Apps" "Win32 CDN (swdin01)" "swdin01-mscdn.manage.microsoft.com" 443 $false "[2] ID:170"
Add-EP "Intune - Win32 Apps" "Win32 CDN (swdin02)" "swdin02-mscdn.manage.microsoft.com" 443 $false "[2] ID:170"

# ----------------------------------------------------------------------
# INTUNE - SCRIPTS & IME CDN (Region-specific)
# ----------------------------------------------------------------------
$imeCDN = switch ($Region) {
    "Global" {
        @(
            @{ N = "IME CDN Primary (NA)";   U = "imeswda-afd-primary.manage.microsoft.com" }
            @{ N = "IME CDN Secondary (NA)"; U = "imeswda-afd-secondary.manage.microsoft.com" }
            @{ N = "IME CDN Hotfix (NA)";    U = "imeswda-afd-hotfix.manage.microsoft.com" }
            @{ N = "IME CDN Primary (EU)";   U = "imeswdb-afd-primary.manage.microsoft.com" }
            @{ N = "IME CDN Secondary (EU)"; U = "imeswdb-afd-secondary.manage.microsoft.com" }
            @{ N = "IME CDN Hotfix (EU)";    U = "imeswdb-afd-hotfix.manage.microsoft.com" }
        )
    }
    "AsiaPacific" {
        @(
            @{ N = "IME CDN Primary (AP)";   U = "imeswdc-afd-primary.manage.microsoft.com" }
            @{ N = "IME CDN Secondary (AP)"; U = "imeswdc-afd-secondary.manage.microsoft.com" }
            @{ N = "IME CDN Hotfix (AP)";    U = "imeswdc-afd-hotfix.manage.microsoft.com" }
        )
    }
}
foreach ($cdn in $imeCDN) {
    Add-EP "Intune - Scripts/IME" $cdn.N $cdn.U 443 $false "[2] Scripts/Win32"
}

# ----------------------------------------------------------------------
# INTUNE - DELIVERY OPTIMIZATION [Ref 2 ID:172]
# ----------------------------------------------------------------------
Add-EP "Intune - Delivery Opt" "DO Discovery" "do.dsp.mp.microsoft.com"      443 $false "[2] ID:172"
Add-EP "Intune - Delivery Opt" "DO Download"  "dl.delivery.mp.microsoft.com" 443 $false "[2] ID:172"

# ----------------------------------------------------------------------
# INTUNE - FEATURE DEPLOYMENT [Ref 2 ID:189,190,192]
# ----------------------------------------------------------------------
Add-EP "Intune - Dependencies" "Feature Config (Edge/Skype)"  "config.edge.skype.com"                               443 $false "[2] ID:189"
Add-EP "Intune - Dependencies" "Feature Config (ECS)"         "ecs.office.com"                                      443 $false "[2] ID:189"
Add-EP "Intune - Dependencies" "Endpoint Discovery"           "go.microsoft.com"                                    443 $false "[2] ID:190"
Add-EP "Intune - Dependencies" "Organizational Messages"      "fd.api.orgmsg.microsoft.com"                         443 $false "[2] ID:192"
Add-EP "Intune - Dependencies" "Org Messages Personalization" "ris.prod.api.personalization.ideas.microsoft.com"    443 $false "[2] ID:192"

# ----------------------------------------------------------------------
# INTUNE - AZURE ATTESTATION (Region-specific)
# ----------------------------------------------------------------------
$attestation = switch ($Region) {
    "Global" {
        @(
            @{ N = "Attestation (EUS)";  U = "intunemaape1.eus.attest.azure.net" }
            @{ N = "Attestation (EUS2)"; U = "intunemaape2.eus2.attest.azure.net" }
            @{ N = "Attestation (CUS)";  U = "intunemaape3.cus.attest.azure.net" }
            @{ N = "Attestation (WUS)";  U = "intunemaape4.wus.attest.azure.net" }
            @{ N = "Attestation (SCUS)"; U = "intunemaape5.scus.attest.azure.net" }
            @{ N = "Attestation (NCUS)"; U = "intunemaape6.ncus.attest.azure.net" }
            @{ N = "Attestation (NEU1)"; U = "intunemaape7.neu.attest.azure.net" }
            @{ N = "Attestation (NEU2)"; U = "intunemaape8.neu.attest.azure.net" }
            @{ N = "Attestation (NEU3)"; U = "intunemaape9.neu.attest.azure.net" }
            @{ N = "Attestation (WEU1)"; U = "intunemaape10.weu.attest.azure.net" }
            @{ N = "Attestation (WEU2)"; U = "intunemaape11.weu.attest.azure.net" }
            @{ N = "Attestation (WEU3)"; U = "intunemaape12.weu.attest.azure.net" }
        )
    }
    "AsiaPacific" {
        @(
            @{ N = "Attestation (JPE1)"; U = "intunemaape13.jpe.attest.azure.net" }
            @{ N = "Attestation (JPE2)"; U = "intunemaape17.jpe.attest.azure.net" }
            @{ N = "Attestation (JPE3)"; U = "intunemaape18.jpe.attest.azure.net" }
            @{ N = "Attestation (JPE4)"; U = "intunemaape19.jpe.attest.azure.net" }
        )
    }
}
foreach ($att in $attestation) {
    Add-EP "Intune - Attestation" $att.N $att.U 443 $false "[2] DHA/MAA"
}

# ----------------------------------------------------------------------
# INTUNE - MACOS CDN (Region-specific)
# ----------------------------------------------------------------------
$macCDN = switch ($Region) {
    "Global" {
        @(
            @{ N = "macOS Sidecar CDN (NA)"; U = "macsidecar.manage.microsoft.com" }
            @{ N = "macOS Sidecar CDN (EU)"; U = "macsidecareu.manage.microsoft.com" }
        )
    }
    "AsiaPacific" {
        @(
            @{ N = "macOS Sidecar CDN (AP)"; U = "macsidecarap.manage.microsoft.com" }
        )
    }
}
foreach ($mac in $macCDN) {
    Add-EP "Intune - macOS" $mac.N $mac.U 443 $false "[2] macOS Apps/Scripts"
}

# ----------------------------------------------------------------------
# WINDOWS PUSH NOTIFICATIONS [Ref 2 ID:171]
# ----------------------------------------------------------------------
Add-EP "Windows - WNS" "WNS (wns.windows.com)"    "wns.windows.com"        443 $false "[2] ID:171"
Add-EP "Windows - WNS" "WNS (notify.windows.com)" "notify.windows.com"     443 $false "[2] ID:171"
Add-EP "Windows - WNS" "WNS (sin.notify)"         "sin.notify.windows.com" 443 $false "[2] ID:171"

# ----------------------------------------------------------------------
# WINDOWS AUTOPILOT [Ref 2 ID:164,165,169,173]
# ----------------------------------------------------------------------
Add-EP "Windows - Autopilot" "Passport Client Config"      "clientconfig.passport.net"          443 $false "[2] ID:169"
Add-EP "Windows - Autopilot" "Windows Phone"               "windowsphone.com"                   443 $false "[2] ID:169"
Add-EP "Windows - Autopilot" "S-Microsoft CDN"             "c.s-microsoft.com"                  443 $false "[2] ID:169"
Add-EP "Windows - Autopilot" "TPM Attestation (Intel)"     "ekop.intel.com"                     443 $false "[2] ID:173"
Add-EP "Windows - Autopilot" "TPM Attestation (Microsoft)" "ekcert.spserv.microsoft.com"        443 $false "[2] ID:173"
Add-EP "Windows - Autopilot" "TPM Attestation (AMD)"       "ftpm.amd.com"                       443 $false "[2] ID:173"
Add-EP "Windows - Autopilot" "Autopilot Diag Upload (EU)"  "lgmsapeweu.blob.core.windows.net"   443 $false "[2] ID:182"

# ----------------------------------------------------------------------
# WINDOWS OS SERVICES
# ----------------------------------------------------------------------
Add-EP "Windows - OS" "Windows Update"                    "update.microsoft.com"                         443 $false "[2] ID:164"
Add-EP "Windows - OS" "Windows Update (windowsupdate)"    "windowsupdate.com"                            443 $false "[2] ID:164"
Add-EP "Windows - OS" "Windows Update (download)"         "download.microsoft.com"                       443 $false "[2] ID:164"
Add-EP "Windows - OS" "Autopilot Download (adl)"          "adl.windows.com"                              443 $false "[2] ID:164"
Add-EP "Windows - OS" "Traffic Shaping (DO)"              "tsfe.trafficshaping.dsp.mp.microsoft.com"     443 $false "[2] ID:164"
Add-EP "Windows - OS" "NTP Time Sync"                     "time.windows.com"                             443 $false "[2] ID:165" "Also uses UDP 123"
Add-EP "Windows - OS" "Telemetry / Diagnostics"           "v10c.events.data.microsoft.com"               443 $false "[2] EPM/IME"
Add-EP "Windows - OS" "Telemetry (Visual Studio)"         "dc.services.visualstudio.com"                 443 $false "[MS] Telemetry" "" $true
Add-EP "Windows - OS" "Client Config (P-Net)"             "clientconfig.microsoftonline-p.net"           443 $false "[MS] Support Services" "" $true
Add-EP "Windows - OS" "Device Health Attestation (Win10)" "has.spserv.microsoft.com"                     443 $false "[2] DHA Win10"

# ----------------------------------------------------------------------
# MICROSOFT STORE
# ----------------------------------------------------------------------
Add-EP "Microsoft Store" "Store Catalog"    "displaycatalog.mp.microsoft.com"    443 $false "[2] Store API"
Add-EP "Microsoft Store" "Store Purchase"   "purchase.md.mp.microsoft.com"       443 $false "[2] Store API"
Add-EP "Microsoft Store" "Store Licensing"  "licensing.mp.microsoft.com"         443 $false "[2] Store API"
Add-EP "Microsoft Store" "Store Edge CDN"   "storeedgefd.dsx.mp.microsoft.com"   443 $false "[2] Store API"

# ----------------------------------------------------------------------
# INTUNE - REMOTE HELP [Ref 2 ID:181,187]
# ----------------------------------------------------------------------
Add-EP "Intune - Remote Help" "Remote Help Portal"    "remotehelp.microsoft.com"                             443 $false "[2] ID:181"
Add-EP "Intune - Remote Help" "Remote Assistance ACS" "remoteassistanceprodacs.communication.azure.com"      443 $false "[2] ID:181"
Add-EP "Intune - Remote Help" "Edge (Skype)"          "edge.skype.com"                                       443 $false "[2] ID:181"
Add-EP "Intune - Remote Help" "Edge (Microsoft)"      "edge.microsoft.com"                                   443 $false "[2] ID:181"
Add-EP "Intune - Remote Help" "WCP Static"            "wcpstatic.microsoft.com"                              443 $false "[2] ID:181"

# ----------------------------------------------------------------------
# INTUNE - ANDROID AOSP [Ref 2 ID:179]
# ----------------------------------------------------------------------
Add-EP "Intune - Android AOSP" "AOSP CDN" "intunecdnpeasd.manage.microsoft.com" 443 $false "[2] ID:179"

# ----------------------------------------------------------------------
# CERTIFICATE VALIDATION / PKI
# ----------------------------------------------------------------------
Add-EP "PKI / CRL" "Microsoft CRL"        "crl.microsoft.com"    80 $true  "[1][2]"
Add-EP "PKI / CRL" "DigiCert CRL"         "crl3.digicert.com"    80 $false "[2]"
Add-EP "PKI / CRL" "OCSP (DigiCert)"      "ocsp.digicert.com"    80 $true  "[2]"
Add-EP "PKI / CRL" "OCSP (Microsoft)"     "ocsp.msocsp.com"      80 $true  "[2]"
Add-EP "PKI / CRL" "Microsoft PKI (www)"  "www.microsoft.com"    80 $false "[2]"

# ----------------------------------------------------------------------
# TEST FUNCTIONS
# ----------------------------------------------------------------------

function Test-TcpPort {
    param(
        [string]$HostName,
        [int]$Port,
        [int]$TimeoutMs = 4000
    )

    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $task = $tcp.BeginConnect($HostName, $Port, $null, $null)
        $ok = $task.AsyncWaitHandle.WaitOne($TimeoutMs, $false)

        if ($ok -and $tcp.Connected) {
            $tcp.EndConnect($task)
            $tcp.Close()
            return $true
        }

        $tcp.Close()
        return $false
    }
    catch {
        return $false
    }
}

function Test-DnsResolve {
    param([string]$HostName)

    try {
        $result = [System.Net.Dns]::GetHostAddresses($HostName)
        if ($result.Count -gt 0) {
            return $result[0].IPAddressToString
        }
        return "FAILED"
    }
    catch {
        return "FAILED"
    }
}

function Test-TlsHandshake {
    param(
        [string]$HostName,
        [int]$Port = 443
    )

    if ($Port -ne 443) {
        return "N/A (HTTP)"
    }

    try {
        $tcp = New-Object System.Net.Sockets.TcpClient($HostName, $Port)
        $ssl = New-Object System.Net.Security.SslStream(
            $tcp.GetStream(),
            $false,
            ([System.Net.Security.RemoteCertificateValidationCallback] { $true })
        )

        $ssl.AuthenticateAsClient($HostName)
        $proto = $ssl.SslProtocol
        $issuer = $ssl.RemoteCertificate.Issuer

        $ssl.Close()
        $tcp.Close()

        if ($issuer -match "O=([^,]+)") {
            $issuer = $Matches[1]
        }

        return "$proto | $issuer"
    }
    catch {
        return "FAILED"
    }
}

# ----------------------------------------------------------------------
# EXECUTION
# ----------------------------------------------------------------------

Clear-Host
Write-Host ""
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "   Entra ID & Intune Connectivity Checker v2.1" -ForegroundColor Cyan
Write-Host "   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $env:COMPUTERNAME | PS $($PSVersionTable.PSVersion)" -ForegroundColor DarkCyan
Write-Host "   User: $env:USERDOMAIN\$env:USERNAME | Admin: $(if ($IsAdmin) { 'YES' } else { 'NO' })" -ForegroundColor DarkCyan
Write-Host "   Region: $Region | Endpoints: $($Endpoints.Count)" -ForegroundColor DarkCyan
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host ""

$Results = [System.Collections.ArrayList]::new()
$total = $Endpoints.Count
$i = 0

foreach ($ep in $Endpoints) {
    $i++
    $pct = [math]::Round(($i / $total) * 100)

    Write-Host "`r  [$pct%] ($i/$total) Testing: $($ep.URL):$($ep.Port)                              " -NoNewline -ForegroundColor DarkGray

    $dns = Test-DnsResolve -HostName $ep.URL
    $tcp = Test-TcpPort -HostName $ep.URL -Port $ep.Port
    $tls = if ($tcp) { Test-TlsHandshake -HostName $ep.URL -Port $ep.Port } else { "N/A" }

    $status = if ($dns -eq "FAILED") {
        "DNS_FAIL"
    }
    elseif (-not $tcp) {
        "TCP_BLOCKED"
    }
    elseif ($tls -eq "FAILED" -and $ep.Port -eq 443) {
        "TLS_FAIL"
    }
    else {
        "OK"
    }

    [void]$Results.Add([PSCustomObject]@{
        RunByUser       = $RunByUser
        Admin           = $(if ($IsAdmin) { "YES" } else { "NO" })
        GeoRegion       = $ep.GeoRegion
        Category        = $ep.Category
        Name            = $ep.Name
        Endpoint        = "$($ep.URL):$($ep.Port)"
        DNS_IP          = $dns
        TCP             = $(if ($tcp) { "Open" } else { "Blocked" })
        TLS             = $tls
        Status          = $status
        Critical        = $(if ($ep.Critical) { "YES" } else { "no" })
        NoSSLInspection = $(if ($ep.NoSSLInspection) { "REQUIRED" } else { "Optional" })
        Ref             = $ep.Ref
        Note            = $ep.Note
    })
}

Write-Host "`r  [100%] Done. Tested $total endpoints.                                       " -ForegroundColor Green
Write-Host ""

# ----------------------------------------------------------------------
# SUMMARY COUNTS
# ----------------------------------------------------------------------
$passCount = ($Results | Where-Object { $_.Status -eq "OK" }).Count
$failCount = ($Results | Where-Object { $_.Status -ne "OK" -and $_.Critical -eq "YES" }).Count
$warnCount = ($Results | Where-Object { $_.Status -ne "OK" -and $_.Critical -eq "no" }).Count

Write-Host "  +-----------------------------------------+" -ForegroundColor White
Write-Host "  |  RESULTS:  " -NoNewline -ForegroundColor White
Write-Host "$passCount PASS" -NoNewline -ForegroundColor Green
Write-Host "  |  " -NoNewline -ForegroundColor White
Write-Host "$failCount CRITICAL FAIL" -NoNewline -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })
Write-Host "  |  " -NoNewline -ForegroundColor White
Write-Host "$warnCount WARN" -NoNewline -ForegroundColor $(if ($warnCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "  |" -ForegroundColor White
Write-Host "  +-----------------------------------------+" -ForegroundColor White
Write-Host ""

# ----------------------------------------------------------------------
# DISPLAY PER CATEGORY
# ----------------------------------------------------------------------
foreach ($cat in ($Results | Select-Object -ExpandProperty Category -Unique)) {
    Write-Host "  -- $cat --" -ForegroundColor Cyan
    $catResults = $Results | Where-Object { $_.Category -eq $cat }

    foreach ($r in $catResults) {
        $icon = switch ($r.Status) {
            "OK"          { "[PASS] " }
            "DNS_FAIL"    { "[DNS!] " }
            "TCP_BLOCKED" { "[BLOCK]" }
            "TLS_FAIL"    { "[TLS!] " }
            default       { "[UNKWN]" }
        }

        $color = switch ($r.Status) {
            "OK"     { if ($r.Critical -eq "YES") { "Green" } else { "DarkGreen" } }
            default  { if ($r.Critical -eq "YES") { "Red" } else { "Yellow" } }
        }

        $crit = if ($r.Critical -eq "YES") { "*" } else { " " }
        $line = "  {0} {1}{2,-44} {3,-52} {4,-8} {5}" -f $icon, $crit, $r.Name, $r.Endpoint, $r.TCP, $r.DNS_IP
        Write-Host $line -ForegroundColor $color
    }

    Write-Host ""
}

Write-Host "  * = Critical endpoint (required for hybrid join / MDM enrollment)" -ForegroundColor DarkGray
Write-Host "  Ref [1] = Entra hybrid join doc  |  Ref [2] = Intune endpoints doc" -ForegroundColor DarkGray
Write-Host ""

# ----------------------------------------------------------------------
# CRITICAL FAILURES DETAIL
# ----------------------------------------------------------------------
$critFails = $Results | Where-Object { $_.Status -ne "OK" -and $_.Critical -eq "YES" }

if ($critFails) {
    Write-Host "  !! ACTION REQUIRED - Critical endpoints failing:" -ForegroundColor Red
    Write-Host "  -------------------------------------------------" -ForegroundColor Red

    foreach ($f in $critFails) {
        Write-Host "     [$($f.Status)] $($f.Endpoint) - $($f.Name)" -ForegroundColor Red
        if ($f.Note) {
            Write-Host "              Note: $($f.Note)" -ForegroundColor DarkYellow
        }
    }

    Write-Host ""
    Write-Host "  Recommendations:" -ForegroundColor Yellow
    Write-Host "    1. Ensure firewall/proxy allows outbound to above endpoints" -ForegroundColor Yellow
    Write-Host "    2. Exempt *.manage.microsoft.com and login.microsoftonline.com from SSL inspection" -ForegroundColor Yellow
    Write-Host "    3. Ensure SYSTEM account has network access (no proxy auth for machine context)" -ForegroundColor Yellow
    Write-Host "    4. Verify DNS resolves correctly from this machine" -ForegroundColor Yellow
    Write-Host ""
}

# ----------------------------------------------------------------------
# TLS INSPECTION WARNING
# ----------------------------------------------------------------------
$tlsFails = $Results | Where-Object { $_.Status -eq "TLS_FAIL" }

if ($tlsFails) {
    Write-Host "  !! TLS HANDSHAKE FAILURES DETECTED:" -ForegroundColor Magenta
    Write-Host "     This may indicate SSL/TLS inspection (proxy break-and-inspect)." -ForegroundColor Magenta
    Write-Host "     Microsoft requires these domains to be excluded from TLS inspection:" -ForegroundColor Magenta
    Write-Host "       - *.manage.microsoft.com" -ForegroundColor Magenta
    Write-Host "       - *.dm.microsoft.com" -ForegroundColor Magenta
    Write-Host "       - device.login.microsoftonline.com" -ForegroundColor Magenta
    Write-Host "       - enterpriseregistration.windows.net" -ForegroundColor Magenta
    Write-Host ""
}

# ----------------------------------------------------------------------
# NON-MICROSOFT TLS ISSUERS (PROXY DETECTION)
# ----------------------------------------------------------------------
$proxyDetected = $Results | Where-Object {
    $_.TLS -ne "N/A" -and
    $_.TLS -ne "N/A (HTTP)" -and
    $_.TLS -ne "FAILED" -and
    $_.TLS -notmatch "Microsoft|DigiCert|Baltimore|GlobalSign|Symantec|GeoTrust|Lets Encrypt|Amazon|Akamai|Cloudflare|Google"
}

if ($proxyDetected) {
    Write-Host "  !! POSSIBLE SSL INSPECTION DETECTED on these endpoints:" -ForegroundColor Magenta
    foreach ($p in $proxyDetected) {
        Write-Host "     $($p.Endpoint) -> Issuer: $($p.TLS)" -ForegroundColor Magenta
    }
    Write-Host "     Non-Microsoft certificate issuers may indicate proxy interception." -ForegroundColor Magenta
    Write-Host ""
}

# ----------------------------------------------------------------------
# CSV EXPORT
# ----------------------------------------------------------------------
if ($ExportCSV) {
    $Results | Export-Csv -Path $CSVPath -NoTypeInformation -Encoding UTF8
    Write-Host "  CSV exported: $CSVPath" -ForegroundColor Green
    Write-Host ""
}

# ----------------------------------------------------------------------
# NETWORK REQUIREMENTS SUMMARY TABLE
# ----------------------------------------------------------------------
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "   NETWORK REQUIREMENTS SUMMARY" -ForegroundColor Cyan
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host ""

$SummaryTable = [System.Collections.ArrayList]::new()
$processedEndpoints = @{}

foreach ($ep in $Endpoints | Sort-Object Category, URL, Port) {
    $key = "$($ep.URL):$($ep.Port)"

    if (-not $processedEndpoints.ContainsKey($key)) {
        $processedEndpoints[$key] = $true

        $protocol = if ($ep.Port -eq 443) {
            "HTTPS"
        }
        elseif ($ep.Port -eq 80) {
            "HTTP"
        }
        else {
            "TCP"
        }

        [void]$SummaryTable.Add([PSCustomObject]@{
            RunByUser       = $RunByUser
            Admin           = $(if ($IsAdmin) { "YES" } else { "NO" })
            GeoRegion       = $ep.GeoRegion
            Category        = $ep.Category
            URL             = $ep.URL
            Port            = $ep.Port
            Protocol        = $protocol
            Critical        = $(if ($ep.Critical) { "YES" } else { "No" })
            NoSSLInspection = $(if ($ep.NoSSLInspection) { "REQUIRED" } else { "Optional" })
            Purpose         = $ep.Name
            Reference       = $ep.Ref
            Notes           = $ep.Note
        })
    }
}

Write-Host "  Total unique network requirements: $($SummaryTable.Count) endpoints" -ForegroundColor White
Write-Host ""

# ----------------------------------------------------------------------
# BASIC REQUIRED / SSL BYPASS LIST
# ----------------------------------------------------------------------
$BasicRequired = [System.Collections.ArrayList]::new()
$noSSLInspectionEndpoints = $Results | Where-Object { $_.NoSSLInspection -eq "REQUIRED" }

foreach ($endpoint in $noSSLInspectionEndpoints) {
    [void]$BasicRequired.Add([PSCustomObject]@{
        RunByUser       = $endpoint.RunByUser
        Admin           = $endpoint.Admin
        Category        = $endpoint.Category
        Name            = $endpoint.Name
        Endpoint        = $endpoint.Endpoint
        URL             = ($endpoint.Endpoint -split ':')[0]
        Port            = ($endpoint.Endpoint -split ':')[1]
        DNS_IP          = $endpoint.DNS_IP
        TCP             = $endpoint.TCP
        TLS             = $endpoint.TLS
        Status          = $endpoint.Status
        Critical        = $endpoint.Critical
        NoSSLInspection = $endpoint.NoSSLInspection
        Ref             = $endpoint.Ref
        Note            = $endpoint.Note
    })
}

Write-Host "  WARNING: $($BasicRequired.Count) endpoints require SSL/TLS inspection bypass" -ForegroundColor Magenta
Write-Host ""

foreach ($cat in ($SummaryTable | Select-Object -ExpandProperty Category -Unique)) {
    Write-Host "  +-- $cat" -ForegroundColor Yellow
    $catSummary = $SummaryTable | Where-Object { $_.Category -eq $cat }

    foreach ($item in $catSummary) {
        $critMarker = if ($item.Critical -eq "YES") { "*" } else { " " }
        $portProtocol = "$($item.Port)/$($item.Protocol)"

        Write-Host "  | $critMarker " -NoNewline -ForegroundColor $(if ($item.Critical -eq "YES") { "Red" } else { "Gray" })
        Write-Host "$($item.URL)" -NoNewline -ForegroundColor White
        Write-Host " : " -NoNewline -ForegroundColor DarkGray
        Write-Host "$portProtocol" -NoNewline -ForegroundColor Cyan

        if ($item.Notes) {
            Write-Host " ($($item.Notes))" -ForegroundColor DarkYellow
        }
        else {
            Write-Host ""
        }
    }

    Write-Host ""
}

Write-Host "  * = Critical endpoint (must be accessible)" -ForegroundColor DarkGray
Write-Host ""

# ----------------------------------------------------------------------
# FIREWALL QUICK REFERENCE
# ----------------------------------------------------------------------
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "   FIREWALL CONFIGURATION QUICK REFERENCE" -ForegroundColor Cyan
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host ""

$portSummary = $SummaryTable | Group-Object Port | Sort-Object Name
Write-Host "  Ports to open (outbound):" -ForegroundColor Yellow
foreach ($port in $portSummary) {
    $protocol = ($port.Group | Select-Object -First 1).Protocol
    $count = $port.Count
    Write-Host "    - Port $($port.Name)/$protocol" -NoNewline -ForegroundColor White
    Write-Host " ($count endpoints)" -ForegroundColor DarkGray
}
Write-Host ""

Write-Host "  Recommended wildcard domain rules:" -ForegroundColor Yellow
$wildcards = @(
    "*.manage.microsoft.com",
    "*.microsoft.com",
    "*.microsoftonline.com",
    "*.windows.net",
    "*.windows.com",
    "*.attest.azure.net",
    "*.core.windows.net",
    "*.digicert.com",
    "*.msauth.net",
    "*.msftauth.net",
    "*.azure.com"
)
foreach ($wc in $wildcards) {
    Write-Host "    - $wc" -ForegroundColor White
}
Write-Host ""

Write-Host "  Important notes:" -ForegroundColor Yellow
Write-Host "    1. SSL/TLS inspection must be DISABLED for the following endpoints:" -ForegroundColor White
Write-Host "       (These are marked as 'NoSSLInspection = REQUIRED' in exported CSV)" -ForegroundColor DarkGray
Write-Host ""

$noSSLEndpoints = $SummaryTable | Where-Object { $_.NoSSLInspection -eq "REQUIRED" } | Select-Object -ExpandProperty URL -Unique
foreach ($endpoint in $noSSLEndpoints) {
    Write-Host "       - $endpoint" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "    2. Proxy authentication must not be required for SYSTEM account" -ForegroundColor White
Write-Host "    3. Allow both IPv4 and IPv6 if available" -ForegroundColor White
Write-Host ""

# ----------------------------------------------------------------------
# EXPORT SUMMARY TABLE
# ----------------------------------------------------------------------
if ($ExportSummaryTable) {
    $SummaryTable | Export-Csv -Path $SummaryCSVPath -NoTypeInformation -Encoding UTF8
    Write-Host "  Network Requirements Summary CSV exported: $SummaryCSVPath" -ForegroundColor Green
    Write-Host ""
}

if (-not $ExportSummaryTable -and -not $ExportCSV) {
    Write-Host "  Tip: Use -ExportSummaryTable to export network requirements to CSV" -ForegroundColor DarkGray
    Write-Host "       Use -ExportCSV to export connectivity test results to CSV" -ForegroundColor DarkGray
    Write-Host ""
}

# ----------------------------------------------------------------------
# RETURN / DISPLAY TABLE INFO
# ----------------------------------------------------------------------
Write-Host ""
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "   SCRIPT COMPLETED - Data Available in Variables" -ForegroundColor Cyan
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Variables created:" -ForegroundColor White
Write-Host "    `$Results         - Connectivity test results ($($Results.Count) tests)" -ForegroundColor Green
Write-Host "    `$SummaryTable    - Network requirements summary ($($SummaryTable.Count) unique endpoints)" -ForegroundColor Green
Write-Host "    `$BasicRequired   - SSL/TLS bypass required endpoints ($($BasicRequired.Count) critical)" -ForegroundColor Magenta
Write-Host ""
Write-Host "  Quick commands:" -ForegroundColor Yellow
Write-Host "    `$Results | Out-GridView        # View connectivity test results" -ForegroundColor Cyan
Write-Host "    `$SummaryTable | Out-GridView   # View network requirements" -ForegroundColor Cyan
Write-Host "    `$BasicRequired | Out-GridView  # View required endpoints that need SSL bypass" -ForegroundColor Magenta
Write-Host ""

Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "   CONNECTIVITY TEST SUMMARY" -ForegroundColor Cyan
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host ""

$summaryStats = [PSCustomObject]@{
    'Total Endpoints Tested' = $Endpoints.Count
    'Passed'                 = ($Results | Where-Object { $_.Status -eq "OK" }).Count
    'Critical Failures'      = ($Results | Where-Object { $_.Status -ne "OK" -and $_.Critical -eq "YES" }).Count
    'Warnings'               = ($Results | Where-Object { $_.Status -ne "OK" -and $_.Critical -eq "no" }).Count
    'Unique URLs Required'   = $SummaryTable.Count
    'SSL Bypass Required'    = $BasicRequired.Count
    'Region'                 = $Region
}
$summaryStats | Format-List

Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "   CONNECTIVITY TEST RESULTS (Top 20)" -ForegroundColor Cyan
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host ""
$Results | Select-Object -First 20 Category, Name, Endpoint, Status, TCP, Critical | Format-Table -AutoSize

if ($Results.Count -gt 20) {
    Write-Host "  ... and $($Results.Count - 20) more results. Use `$Results | Out-GridView to see all" -ForegroundColor DarkGray
    Write-Host ""
}

Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "   NETWORK REQUIREMENTS (Top 20)" -ForegroundColor Cyan
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host ""
$SummaryTable | Select-Object -First 20 Category, URL, Port, Protocol, Critical | Format-Table -AutoSize

if ($SummaryTable.Count -gt 20) {
    Write-Host "  ... and $($SummaryTable.Count - 20) more requirements. Use `$SummaryTable | Out-GridView to see all" -ForegroundColor DarkGray
    Write-Host ""
}

Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "   BASIC REQUIRED ENDPOINTS (SSL/TLS Bypass Required)" -ForegroundColor Cyan
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host ""
$BasicRequired | Select-Object -First 15 Name, Endpoint, Status, TCP, NoSSLInspection | Format-Table -AutoSize

if ($BasicRequired.Count -gt 15) {
    Write-Host "  ... and $($BasicRequired.Count - 15) more endpoints. Use `$BasicRequired | Out-GridView to see all" -ForegroundColor DarkGray
    Write-Host ""
}

Write-Host "  ======================================================================" -ForegroundColor Yellow
Write-Host "  WHICH TABLE SHOULD I USE? - QUICK REFERENCE" -ForegroundColor Yellow
Write-Host "  ======================================================================" -ForegroundColor Yellow
Write-Host ""

Write-Host "  TABLE 1: `$Results = 'DID IT WORK?'" -ForegroundColor Cyan
Write-Host ""
Write-Host "     WHAT IT IS:" -ForegroundColor White
Write-Host "        - DIAGNOSTIC DATA - Shows what happened when testing" -ForegroundColor Gray
Write-Host "        - Contains: DNS resolution, TCP connectivity, TLS handshake" -ForegroundColor Gray
Write-Host "        - Purpose: Troubleshooting connectivity problems" -ForegroundColor Gray
Write-Host ""
Write-Host "     WHEN TO USE:" -ForegroundColor White
Write-Host "        - Finding what's broken (which endpoints failed)" -ForegroundColor Gray
Write-Host "        - Seeing why it failed (DNS, firewall, SSL)" -ForegroundColor Gray
Write-Host "        - Creating troubleshooting reports for IT team" -ForegroundColor Gray
Write-Host ""
Write-Host "     EXAMPLE:" -ForegroundColor White
Write-Host "        `$Results | Out-GridView" -ForegroundColor Yellow
Write-Host "        `$Results | Where-Object Status -ne 'OK' | Out-GridView" -ForegroundColor Yellow
Write-Host ""

Write-Host "  TABLE 2: `$SummaryTable = 'WHAT DO I NEED?'" -ForegroundColor Cyan
Write-Host ""
Write-Host "     WHAT IT IS:" -ForegroundColor White
Write-Host "        - CONFIGURATION DATA - Lists what should be allowed in firewall" -ForegroundColor Gray
Write-Host "        - Contains: Unique endpoints (deduplicated), no test results" -ForegroundColor Gray
Write-Host "        - Purpose: Configuring network/firewall rules" -ForegroundColor Gray
Write-Host ""
Write-Host "     WHEN TO USE:" -ForegroundColor White
Write-Host "        - Requesting firewall openings from network team" -ForegroundColor Gray
Write-Host "        - Creating allowlist for proxy/firewall" -ForegroundColor Gray
Write-Host "        - Documenting network dependencies" -ForegroundColor Gray
Write-Host ""
Write-Host "     EXAMPLE:" -ForegroundColor White
Write-Host "        `$SummaryTable | Out-GridView" -ForegroundColor Yellow
Write-Host "        `$SummaryTable | Where-Object Critical -eq 'YES' | Out-GridView" -ForegroundColor Yellow
Write-Host ""

Write-Host "  TABLE 3: `$BasicRequired = 'WHAT MUST BYPASS SSL?'" -ForegroundColor Cyan
Write-Host ""
Write-Host "     WHAT IT IS:" -ForegroundColor White
Write-Host "        - CRITICAL SECURITY CONFIG - Endpoints that will fail if proxied" -ForegroundColor Gray
Write-Host "        - Contains: Endpoints requiring SSL/TLS inspection bypass" -ForegroundColor Gray
Write-Host "        - Purpose: Configuring proxy exclusions / SSL bypass rules" -ForegroundColor Gray
Write-Host ""
Write-Host "     WHEN TO USE:" -ForegroundColor White
Write-Host "        - Configuring SSL bypass on proxy/firewall" -ForegroundColor Gray
Write-Host "        - Troubleshooting device join / enrollment issues" -ForegroundColor Gray
Write-Host "        - Fixing MDM enrollment failures" -ForegroundColor Gray
Write-Host ""
Write-Host "     EXAMPLE:" -ForegroundColor White
Write-Host "        `$BasicRequired | Out-GridView" -ForegroundColor Yellow
Write-Host "        `$BasicRequired | Select-Object URL -Unique" -ForegroundColor Yellow
Write-Host ""

Write-Host "  ======================================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "  QUICK ACTIONS:" -ForegroundColor Cyan
Write-Host ""
Write-Host "     View all connectivity failures:" -ForegroundColor White
Write-Host "     > `$Results | Where-Object Status -ne 'OK' | Out-GridView" -ForegroundColor Yellow
Write-Host ""
Write-Host "     View all critical endpoints:" -ForegroundColor White
Write-Host "     > `$SummaryTable | Where-Object Critical -eq 'YES' | Out-GridView" -ForegroundColor Yellow
Write-Host ""
Write-Host "     View SSL bypass requirements:" -ForegroundColor White
Write-Host "     > `$BasicRequired | Out-GridView" -ForegroundColor Yellow
Write-Host ""
Write-Host "     Export all data to CSV:" -ForegroundColor White
Write-Host "     > `$Results | Export-Csv Desktop\ConnectivityResults.csv -NoTypeInformation" -ForegroundColor Yellow
Write-Host "     > `$SummaryTable | Export-Csv Desktop\NetworkRequirements.csv -NoTypeInformation" -ForegroundColor Yellow
Write-Host "     > `$BasicRequired | Export-Csv Desktop\SSL_Bypass_List.csv -NoTypeInformation" -ForegroundColor Yellow
Write-Host ""
Write-Host "  ======================================================================" -ForegroundColor Green
Write-Host "  SUMMARY - Copy this for your documentation:" -ForegroundColor Green
Write-Host "  ======================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  `$Results = 'DID IT WORK?'" -ForegroundColor Cyan
Write-Host "    -> DIAGNOSTIC DATA - Shows what happened when testing" -ForegroundColor Gray
Write-Host "    -> Contains: DNS resolution, TCP connectivity, TLS handshake" -ForegroundColor Gray
Write-Host "    -> Purpose: Troubleshooting connectivity problems" -ForegroundColor Gray
Write-Host ""
Write-Host "  `$SummaryTable = 'WHAT DO I NEED?'" -ForegroundColor Cyan
Write-Host "    -> CONFIGURATION DATA - Lists what should be allowed in firewall" -ForegroundColor Gray
Write-Host "    -> Contains: Unique endpoints (deduplicated), no test results" -ForegroundColor Gray
Write-Host "    -> Purpose: Configuring network/firewall rules" -ForegroundColor Gray
Write-Host ""
Write-Host "  `$BasicRequired = 'WHAT MUST BYPASS SSL?'" -ForegroundColor Cyan
Write-Host "    -> CRITICAL SECURITY CONFIG - Endpoints that will fail if proxied" -ForegroundColor Gray
Write-Host "    -> Contains: Endpoints requiring SSL/TLS inspection bypass" -ForegroundColor Gray
Write-Host "    -> Purpose: Configuring proxy exclusions / SSL bypass rules" -ForegroundColor Gray
Write-Host ""
Write-Host "  ======================================================================" -ForegroundColor Green
Write-Host ""