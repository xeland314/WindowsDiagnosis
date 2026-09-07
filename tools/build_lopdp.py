import pathlib
dst = pathlib.Path(r"C:\Users\ASUS\workspace\WindowsDiagnosis\Auditoria-LOPDP-Endpoint.ps1")
content = r"""<#
.SYNOPSIS
    Auditoria de seguridad de endpoint - Cumplimiento LOPDP Art.10 y 38 (Ecuador).
.DESCRIPTION
    Verifica en Windows las 5 protecciones basicas exigidas por la Ley Organica de
    Proteccion de Datos Personales (LOPDP) para estaciones que manejan datos
    personales/financieros. Cada hallazgo se presenta con semaforo rojo/verde
    y guia de mitigacion para auditoria ante la Superintendencia.

    Bloques:
    1) Cifrado de disco (BitLocker) - riesgo robo/perdida de equipo
    2) Puertos en escucha expuestos (RDP 3389, SMB 445, RPC 135, etc.)
    3) Firewall de Windows (perfiles Dominio/Privado/Publico)
    4) Antivirus / Defender (servicio, proteccion tiempo real, firmas)
    5) Cuentas con privilegios de Administrador local (principio menor privilegio)

    Sin dependencias. Compatible PowerShell 5.1 y 7+. Requiere ejecucion como
    Administrador para BitLocker, Firewall y enumeracion de admins; sin Admin
    muestra aviso en vez de "todo ok".
.NOTES
    Ejecutar: powershell -ExecutionPolicy Bypass -File .\Auditoria-LOPDP-Endpoint.ps1
    Si viene de USB/otra PC: Unblock-File -Path .\Auditoria-LOPDP-Endpoint.ps1
#>

#Requires -Version 5.1
$ErrorActionPreference = "SilentlyContinue"

function ConvertTo-HtmlEscaped {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

$ReportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ComputerName = $env:COMPUTERNAME
$OutputFile = "$env:USERPROFILE\Desktop\Auditoria_LOPDP_$ComputerName_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"

$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " Auditoria LOPDP Endpoint - $ComputerName" -ForegroundColor Cyan
if (-not $isElevated) { Write-Host " ADVERTENCIA: No es sesion Administrador. BitLocker/Firewall/Admins saldran como 'no verificado'." -ForegroundColor Yellow }
Write-Host "==================================================" -ForegroundColor Cyan

# ----------------------------------------------------
# 1. CIFRADO DE DISCO (BitLocker) - LOPDP Art.38
# ----------------------------------------------------
Write-Host "[1/10] Verificando cifrado de disco (BitLocker)..." -ForegroundColor Yellow
$bitlockerRows = ""
$bitlockerSummary = ""
$bitlockerBad = 0
$bitlockerTotal = 0
try {
    $vols = @()
    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        $vols = Get-BitLockerVolume -ErrorAction Stop
    } else {
        # Fallback CIM para Windows 10 Home / sin modulo BitLocker
        $cims = Get-CimInstance -Namespace "root\CIMv2\Security\MicrosoftVolumeEncryption" -ClassName Win32_EncryptableVolume -ErrorAction Stop
        foreach ($c in $cims) {
            $letter = $c.DriveLetter
            $prot = $c.ProtectionStatus  # 0=OFF, 1=ON, 2=UNKNOWN
            $enc = $c.EncryptionMethod
            # Mapear a objeto compatible con Get-BitLockerVolume
            $vols += [PSCustomObject]@{
                MountPoint = $letter
                ProtectionStatus = switch ($prot) { 1 { "On" } 0 { "Off" } default { "Unknown" } }
                VolumeStatus = if ($prot -eq 1) { "FullyEncrypted" } else { "FullyDecrypted" }
                EncryptionPercentage = if ($prot -eq 1) { 100 } else { 0 }
                KeyProtector = @()
                _RawProt = $prot
            }
        }
    }
    if ($vols -and $vols.Count -gt 0) {
        $bitlockerTotal = $vols.Count
        foreach ($v in $vols) {
            $mp = if ($v.MountPoint) { $v.MountPoint } elseif ($v.DriveLetter) { $v.DriveLetter } else { "N/D" }
            # Normalizar ProtectionStatus a texto y badge
            $protText = ""
            $badge = "bad"
            $isProtected = $false
            if ($v.ProtectionStatus -is [string]) {
                $protText = $v.ProtectionStatus
                $isProtected = ($protText -eq "On" -or $protText -eq "ProtectionOn")
            } elseif ($v.PSObject.Properties["_RawProt"]) {
                $protText = if ($v._RawProt -eq 1) { "On" } else { "Off" }
                $isProtected = ($v._RawProt -eq 1)
            } else {
                # Get-BitLockerVolume: VolumeStatus
                $protText = $v.VolumeStatus
                $isProtected = ($v.VolumeStatus -like "*Encrypted*" -and $v.ProtectionStatus -ne "Off")
                if ($v.ProtectionStatus -eq "On") { $isProtected = $true }
            }
            # EncryptionPercentage si existe
            $pct = ""
            if ($null -ne $v.EncryptionPercentage) { $pct = "$($v.EncryptionPercentage)%" } else { "N/D" }
            if ($isProtected) {
                $badge = "ok"
            } else {
                $badge = "bad"
                $bitlockerBad++
            }
            # KeyProtector resumen
            $kp = ""
            try {
                if ($v.KeyProtector -and $v.KeyProtector.Count -gt 0) {
                    $kp = ($v.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ", "
                } else { $kp = "N/D" }
            } catch { $kp = "N/D" }
            $mpEsc = ConvertTo-HtmlEscaped $mp
            $pctEsc = ConvertTo-HtmlEscaped $pct
            $kpEsc = ConvertTo-HtmlEscaped $kp
            $protEsc = ConvertTo-HtmlEscaped $protText
            $bitlockerRows += "<tr><td><strong>$mpEsc</strong></td><td><span class='badge $badge'>$protEsc</span></td><td>$pctEsc</td><td>$kpEsc</td></tr>"
        }
        if ($bitlockerBad -gt 0) {
            $bitlockerSummary = "<span class='badge bad'>$bitlockerBad de $bitlockerTotal unidad(es) SIN cifrado</span>"
        } else {
            $bitlockerSummary = "<span class='badge ok'>$bitlockerTotal unidad(es) protegida(s)</span>"
        }
    } else {
        $bitlockerRows = "<tr><td colspan='4' class='text-muted'>No se detectaron volumenes BitLocker (posible Home sin BitLocker o sin permisos).</td></tr>"
        $bitlockerSummary = "<span class='badge warn'>Sin datos</span>"
    }
} catch {
    $bitlockerRows = "<tr><td colspan='4' class='text-muted'>No se pudo consultar BitLocker (requiere Admin o no soportado): $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
    $bitlockerSummary = "<span class='badge warn'>No verificado</span>"
    if (-not $isElevated) { $bitlockerBad = 0 }
    else { $bitlockerBad = 1 }
}
$bitlockerCardClass = if ($bitlockerBad -gt 0) { "card-bad" } elseif ($bitlockerSummary -like "*Sin datos*") { "" } else { "card-ok" }

# ----------------------------------------------------
# 2. PUERTOS ABIERTOS EN ESCUCHA - Exposicion de red local
# ----------------------------------------------------
Write-Host "[2/10] Auditando puertos en escucha (RDP/SMB/RPC...)" -ForegroundColor Yellow
$riskPorts = @(3389,445,135,21,22,23,80,443,5985,5986)
$riskNames = @{ 3389="RDP"; 445="SMB"; 135="RPC"; 21="FTP"; 22="SSH"; 23="Telnet"; 80="HTTP"; 443="HTTPS"; 5985="WinRM-HTTP"; 5986="WinRM-HTTPS" }
# Puertos que NO deben contarse como 'bad' directo sin contexto de firewall - se marcan 'warn'
$portsFirewallSensitive = @(445,135)
$portsWarnOnly = @(80,443,5985,5986)
$listenRows = ""
$listenBad = 0
$listenWarn = 0
# Necesitamos estado del firewall antes para cruzar exposicion: si firewall bloquea entrante, el riesgo es menor
$fwProfilesForPorts = $null
$fwBlockingAll = $false
try {
    $fwProfilesForPorts = Get-NetFirewallProfile -ErrorAction Stop
    $fwBlockingAll = $true
    foreach ($fp in $fwProfilesForPorts) {
        $isOn = ($fp.Enabled -eq $true -or $fp.Enabled -eq 1 -or $fp.Enabled -eq "True")
        $inBlock = ($fp.DefaultInboundAction -eq "Block" -or $fp.DefaultInboundAction -eq 1)
        if (-not $isOn -or -not $inBlock) { $fwBlockingAll = $false }
    }
} catch { $fwBlockingAll = $false }
try {
    $listens = Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { ($_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::' -or $_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress.StartsWith("0.")) -and ($riskPorts -contains $_.LocalPort) }
    if (-not $listens -or $listens.Count -eq 0) {
        $listens = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $riskPorts -contains $_.LocalPort }
        $listens = $listens | Where-Object { $_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::' -or $_.LocalAddress -eq '0.0.0.0' }
    }
    if ($listens -and $listens.Count -gt 0) {
        foreach ($ln in $listens) {
            $port = $ln.LocalPort
            $svc = if ($riskNames.ContainsKey($port)) { $riskNames[$port] } else { "Servicio $port" }
            $addr = ConvertTo-HtmlEscaped $ln.LocalAddress
            $proc = ""
            try { $proc = (Get-Process -Id $ln.OwningProcess -ErrorAction Stop).ProcessName } catch { $proc = "PID $($ln.OwningProcess)" }
            $procEsc = ConvertTo-HtmlEscaped $proc
            $svcEsc = ConvertTo-HtmlEscaped $svc
            # Clasificacion: 5985/5986 y 80/443 siempre warn, 445/135 con firewall bloqueando = warn, resto bad
            $isWarnOnly = ($portsWarnOnly -contains $port)
            $isFirewallSensitive = ($portsFirewallSensitive -contains $port)
            if ($isWarnOnly) {
                $listenWarn++
                $listenRows += "<tr class='row-bad' style='opacity:0.9'><td>$addr</td><td><span class='badge warn'>$port</span> $svcEsc</td><td>$procEsc ($($ln.OwningProcess))</td><td>Escucha en 0.0.0.0 - Normal si hay PSRemoting/GPO (5985/5986) o web local (80/443). Verificar regla Firewall.</td></tr>"
            } elseif ($isFirewallSensitive -and $fwBlockingAll) {
                $listenWarn++
                $listenRows += "<tr><td>$addr</td><td><span class='badge warn'>$port</span> $svcEsc</td><td>$procEsc ($($ln.OwningProcess))</td><td>Escucha en 0.0.0.0 pero Firewall bloquea entrante por defecto (DefaultInboundAction Block) - Exposicion mitigada. Revisar regla si es necesario compartir.</td></tr>"
            } else {
                $listenBad++
                $listenRows += "<tr class='row-bad'><td>$addr</td><td><span class='badge bad'>$port</span> $svcEsc</td><td>$procEsc ($($ln.OwningProcess))</td><td>Expuesto a toda la red local - Cerrar o restringir por Firewall/VPN</td></tr>"
            }
        }
        if ($listenBad -eq 0 -and $listenWarn -eq 0) {
            $listenRows = "<tr><td colspan='4' class='text-ok'>Ningun puerto critico (3389/445/135...) expuesto en 0.0.0.0/:: (correcto).</td></tr>"
        }
    } else {
        $listenRows = "<tr><td colspan='4' class='text-ok'>Ningun puerto critico (3389/445/135...) expuesto en 0.0.0.0/:: (correcto).</td></tr>"
    }
} catch {
    try {
        $ns = netstat -ano 2>&1 | Select-String "LISTENING"
        $found = @()
        foreach ($line in $ns) {
            foreach ($rp in $riskPorts) {
                if ($line -match ":$rp\s") { $found += $line.Line.Trim() }
            }
        }
        if ($found.Count -gt 0) {
            $listenWarn = $found.Count
            foreach ($f in ($found | Select-Object -First 20)) {
                $listenRows += "<tr class='row-bad'><td colspan='4'>$(ConvertTo-HtmlEscaped $f) <span class='badge warn'>Revisar + Firewall</span></td></tr>"
            }
        } else {
            $listenRows = "<tr><td colspan='4' class='text-ok'>netstat no reporta puertos criticos en escucha.</td></tr>"
        }
    } catch {
        $listenRows = "<tr><td colspan='4' class='text-muted'>No se pudo auditar puertos: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
    }
}
$listenSummary = if ($listenBad -gt 0) { "<span class='badge bad'>$listenBad puerto(s) critico(s)</span> $(if($listenWarn -gt 0){"<span class='badge warn'>$listenWarn en modo warn (Firewall/PSRemoting)</span>"})" } elseif ($listenWarn -gt 0) { "<span class='badge warn'>$listenWarn puerto(s) en escucha (mitigado por Firewall/PSRemoting)</span>" } else { "<span class='badge ok'>Sin exposicion critica</span>" }

# ----------------------------------------------------
# 3. FIREWALL DE WINDOWS
# ----------------------------------------------------
Write-Host "[3/10] Verificando Firewall de Windows..." -ForegroundColor Yellow
$fwRows = ""
$fwBad = 0
try {
    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    foreach ($fw in $profiles) {
        $name = ConvertTo-HtmlEscaped $fw.Name
        $enabled = $fw.Enabled
        # Enabled puede ser boolean o 0/1 segun version
        $isOn = ($enabled -eq $true -or $enabled -eq 1 -or $enabled -eq "True")
        $badge = if ($isOn) { "ok" } else { "bad" }
        $text = if ($isOn) { "Activo" } else { "DESACTIVADO" }
        if (-not $isOn) { $fwBad++ }
        # DefaultInboundAction / DefaultOutboundAction
        $inAct = ConvertTo-HtmlEscaped "$($fw.DefaultInboundAction)"
        $fwRows += "<tr><td>$name</td><td><span class='badge $badge'>$text</span></td><td>$inAct</td></tr>"
    }
    if (-not $fwRows) {
        $fwRows = "<tr><td colspan='3' class='text-muted'>Sin perfiles de firewall detectados.</td></tr>"
    }
} catch {
    $fwRows = "<tr><td colspan='3' class='text-muted'>No se pudo consultar Firewall (requiere Admin): $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
    if (-not $isElevated) { $fwBad = 0 } else { $fwBad = 1 }
}
$fwSummary = if ($fwBad -gt 0) { "<span class='badge bad'>$fwBad perfil(es) desactivado(s)</span>" } else { "<span class='badge ok'>Todos los perfiles activos</span>" }

# ----------------------------------------------------
# 4. ANTIVIRUS / DEFENDER
# ----------------------------------------------------
Write-Host "[4/10] Verificando Antivirus/Defender..." -ForegroundColor Yellow
$avRows = ""
$avBad = 0
$avSummary = ""
try {
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $checks = @(
            @{ Label="Servicio Antimalware (AMService)"; Value=$mp.AMServiceEnabled; Desc="Motor principal" },
            @{ Label="Antivirus habilitado"; Value=$mp.AntivirusEnabled; Desc="Proteccion AV" },
            @{ Label="Proteccion tiempo real"; Value=$mp.RealTimeProtectionEnabled; Desc="Bloqueo en acceso" },
            @{ Label="Proteccion en la nube"; Value=$mp.IsTamperProtected; Desc="Tamper / MAPS" }
        )
        # AntivirusSignatureLastUpdated y QuickScan
        $sigDate = ""
        try { $sigDate = $mp.AntivirusSignatureLastUpdated.ToString("yyyy-MM-dd HH:mm") } catch { $sigDate = "N/D" }
        $sigAgeDays = $null
        try { $sigAgeDays = ((Get-Date) - $mp.AntivirusSignatureLastUpdated).TotalDays } catch {}
        $sigBadge = if ($sigAgeDays -ne $null -and $sigAgeDays -gt 7) { "bad" } elseif ($sigAgeDays -gt 3) { "warn" } else { "ok" }
        if ($sigBadge -eq "bad") { $avBad++ }

        foreach ($chk in $checks) {
            $val = $chk.Value
            $isOn = ($val -eq $true -or $val -eq 1)
            $badge = if ($isOn) { "ok" } else { "bad" }
            $text = if ($isOn) { "Activo" } else { "DESACTIVADO" }
            if (-not $isOn) { $avBad++ }
            $labelEsc = ConvertTo-HtmlEscaped $chk.Label
            $descEsc = ConvertTo-HtmlEscaped $chk.Desc
            $avRows += "<tr><td>$labelEsc</td><td><span class='badge $badge'>$text</span></td><td>$descEsc</td></tr>"
        }
        $sigEsc = ConvertTo-HtmlEscaped $sigDate
        $avRows += "<tr><td>Firmas actualizadas</td><td><span class='badge $sigBadge'>$sigEsc</span></td><td>Si &gt;7 dias, riesgo alto</td></tr>"

        # Comportamiento ante firmas viejas
        if ($avBad -eq 0) { $avSummary = "<span class='badge ok'>Proteccion activa y firmas vigentes</span>" }
        else { $avSummary = "<span class='badge bad'>$avBad hallazgo(s) critico(s)</span>" }
    } else {
        # Fallback SecurityCenter2
        $avProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop
        if ($avProducts) {
            foreach ($av in $avProducts) {
                $name = ConvertTo-HtmlEscaped $av.displayName
                $state = $av.productState
                # 266240 = enabled+updated, 262144 = disabled, etc. Simplificado hex
                $hex = "0x{0:X}" -f $state
                $isOk = ($state -eq 266240 -or $state -eq 397312 -or $state -eq 397344)
                $badge = if ($isOk) { "ok" } else { "bad" }
                if (-not $isOk) { $avBad++ }
                $avRows += "<tr><td>$name</td><td><span class='badge $badge'>$hex</span></td><td>productState WMI</td></tr>"
            }
            $avSummary = if ($avBad -gt 0) { "<span class='badge bad'>$avBad producto(s) con estado no optimo</span>" } else { "<span class='badge ok'>AV activo (SecurityCenter2)</span>" }
        } else {
            $avRows = "<tr><td colspan='3' class='text-muted'>No se detecto AV via Get-MpComputerStatus ni SecurityCenter2 (posible EDR de terceros).</td></tr>"
            $avSummary = "<span class='badge warn'>No verificado (EDR terceros?)</span>"
        }
    }
} catch {
    $avRows = "<tr><td colspan='3' class='text-muted'>No se pudo consultar AV: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
    $avSummary = "<span class='badge warn'>No verificado</span>"
}

# ----------------------------------------------------
# 5. CUENTAS ADMINISTRADOR LOCAL - Principio menor privilegio
# ----------------------------------------------------
Write-Host "[5/10] Auditando cuentas con privilegios de Administrador local..." -ForegroundColor Yellow
$adminRows = ""
$adminCount = 0
$adminBad = 0
try {
    # SID S-1-5-32-544 = Administradores, independiente de idioma (Administrators/Administradores)
    $members = Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop
    # Filtra solo Principals locales para no penalizar Domain Admins en equipo unido a dominio
    $localMembers = $members | Where-Object { $_.PrincipalSource -eq "Local" }
    $domainMembers = $members | Where-Object { $_.PrincipalSource -ne "Local" }
    $adminCount = $localMembers.Count
    if ($adminCount -eq 0) { $adminCount = $members.Count } # fallback si PrincipalSource vacio en build antigua
    $allForDisplay = @()
    if ($localMembers) { $allForDisplay += $localMembers }
    if ($domainMembers) { $allForDisplay += $domainMembers }
    if (-not $allForDisplay -or $allForDisplay.Count -eq 0) { $allForDisplay = $members }
    foreach ($m in $allForDisplay) {
        $name = ConvertTo-HtmlEscaped $m.Name
        $src = ConvertTo-HtmlEscaped $m.PrincipalSource
        $objClass = ConvertTo-HtmlEscaped $m.ObjectClass
        $isDomain = ($src -ne "Local" -and $src -ne "" -and $src -ne $null)
        $isBuiltIn = ($name -like "*Administrator*" -or $name -like "*Administrador*")
        $badge = if ($isDomain) { "warn" } elseif ($isBuiltIn) { "ok" } else { "warn" }
        $badgeText = if ($isDomain) { "Dominio (no cuenta para umbral)" } elseif ($isBuiltIn) { "Sistema" } else { "Revisar" }
        # Solo admins locales cuentan para exceso; Domain Admins ignorados en umbral
        if (-not $isDomain -and -not $isBuiltIn -and $adminCount -gt 3) { $badge = "bad"; $badgeText = "Exceso local"; $adminBad++ }
        $adminRows += "<tr><td>$name</td><td>$objClass</td><td>$src</td><td><span class='badge $badge'>$badgeText</span></td></tr>"
    }
    if ($adminCount -eq 0 -and $allForDisplay.Count -eq 0) {
        $adminRows = "<tr><td colspan='4' class='text-muted'>No se encontraron miembros (inusual).</td></tr>"
    } elseif ($adminCount -gt 3) {
        $adminBad = 1
    }
} catch {
    # Fallback con net localgroup (funciona sin modulo LocalAccounts en Win7/PS antiguo)
    try {
        $out = net localgroup Administradores 2>&1
        if ($LASTEXITCODE -ne 0) { $out = net localgroup Administrators 2>&1 }
        $lines = $out | Where-Object { $_ -match "\S" -and $_ -notmatch "---" -and $_ -notmatch "comando se completo" -and $_ -notmatch "The command" -and $_ -notmatch "Alias|Nombre|Comentario|Miembros" }
        # Ultimas lineas son usuarios
        $users = $lines | Select-Object -Last 10 | Where-Object { $_.Trim() -ne "" }
        foreach ($u in $users) {
            $uEsc = ConvertTo-HtmlEscaped $u.Trim()
            if ($uEsc) { $adminRows += "<tr><td>$uEsc</td><td>N/D</td><td>net localgroup</td><td><span class='badge warn'>Revisar</span></td></tr>"; $adminCount++ }
        }
        if (-not $adminRows) { $adminRows = "<tr><td colspan='4' class='text-muted'>net localgroup no devolvio miembros: $(ConvertTo-HtmlEscaped ($out | Out-String).Substring(0,[math]::Min(300,($out|Out-String).Length)))</td></tr>" }
    } catch {
        $adminRows = "<tr><td colspan='4' class='text-muted'>No se pudo enumerar administradores (requiere Admin): $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
    }
}
$adminSummary = if ($adminCount -eq 0) { "<span class='badge warn'>Sin datos</span>" } elseif ($adminCount -le 2) { "<span class='badge ok'>$adminCount cuenta(s) admin</span>" } elseif ($adminCount -eq 3) { "<span class='badge warn'>$adminCount cuentas - revisar</span>" } else { "<span class='badge bad'>$adminCount cuentas - exceso de privilegios</span>" }

# ----------------------------------------------------
# 6. BLOQUEO DE PANTALLA POR INACTIVIDAD - LOPDP (portatiles contables)
# ----------------------------------------------------
Write-Host "[6/10] Verificando bloqueo de pantalla por inactividad..." -ForegroundColor Yellow
$screenRows = ""
$screenBad = 0
$screenWarn = 0
try {
    $saveActive = $null; $saveSecure = $null; $saveTimeout = $null; $inactivity = $null
    try { $saveActive = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name ScreenSaveActive -ErrorAction Stop).ScreenSaveActive } catch {}
    try { $saveSecure = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name ScreenSaverIsSecure -ErrorAction Stop).ScreenSaverIsSecure } catch {}
    try { $saveTimeout = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name ScreenSaveTimeOut -ErrorAction Stop).ScreenSaveTimeOut } catch {}
    try { $inactivity = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name InactivityTimeoutSecs -ErrorAction Stop).InactivityTimeoutSecs } catch {}
    # Tambien GPO: HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop
    try {
        $gpoActive = (Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name ScreenSaveActive -ErrorAction Stop).ScreenSaveActive
        if ($null -ne $gpoActive) { $saveActive = $gpoActive }
        $gpoSecure = (Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name ScreenSaverIsSecure -ErrorAction Stop).ScreenSaverIsSecure
        if ($null -ne $gpoSecure) { $saveSecure = $gpoSecure }
        $gpoTimeout = (Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name ScreenSaveTimeOut -ErrorAction Stop).ScreenSaveTimeOut
        if ($null -ne $gpoTimeout) { $saveTimeout = $gpoTimeout }
    } catch {}
    $rows = @()
    $rows += [PSCustomObject]@{ Item="ScreenSaveActive (protector)"; Valor="$saveActive"; Esperado="1"; Ok=($saveActive -eq "1" -or $saveActive -eq 1) }
    $rows += [PSCustomObject]@{ Item="ScreenSaverIsSecure (bloqueo)"; Valor="$saveSecure"; Esperado="1"; Ok=($saveSecure -eq "1" -or $saveSecure -eq 1) }
    $rows += [PSCustomObject]@{ Item="ScreenSaveTimeOut (seg)"; Valor="$saveTimeout"; Esperado="<=900 (15 min)"; Ok=($null -ne $saveTimeout -and [int]$saveTimeout -le 900 -and [int]$saveTimeout -gt 0) }
    $rows += [PSCustomObject]@{ Item="InactivityTimeoutSecs (GPO)"; Valor="$(if($null -ne $inactivity){$inactivity}else{"No configurado"})"; Esperado="<=900 o No requerido si protector OK"; Ok=($null -eq $inactivity -or [int]$inactivity -le 900) }
    foreach ($rw in $rows) {
        $badge = if ($rw.Ok) { "ok" } else { "bad" }
        $txt = if ($rw.Ok) { "OK" } else { "Revisar" }
        if (-not $rw.Ok) { if ($rw.Item -like "*Inactivity*") { $screenWarn++ } else { $screenBad++ } }
        $itemEsc = ConvertTo-HtmlEscaped $rw.Item
        $valEsc = ConvertTo-HtmlEscaped $rw.Valor
        $espEsc = ConvertTo-HtmlEscaped $rw.Esperado
        $screenRows += "<tr><td>$itemEsc</td><td>$valEsc</td><td>$espEsc</td><td><span class='badge $badge'>$txt</span></td></tr>"
    }
    if ($screenBad -eq 0 -and $screenWarn -eq 0) { $screenRows += "<tr><td colspan='4' class='text-ok'>Bloqueo por inactividad configurado correctamente.</td></tr>" }
} catch {
    $screenRows = "<tr><td colspan='4' class='text-muted'>No se pudo verificar bloqueo de pantalla: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
    $screenWarn = 1
}
$screenSummary = if ($screenBad -gt 0) { "<span class='badge bad'>$screenBad fallo(s)</span>" } elseif ($screenWarn -gt 0) { "<span class='badge warn'>$screenWarn aviso(s)</span>" } else { "<span class='badge ok'>OK</span>" }

# ----------------------------------------------------
# 7. SALUD DE CUENTAS LOCALES - PasswordRequired, Guest, PasswordLastSet
# ----------------------------------------------------
Write-Host "[7/10] Verificando salud de cuentas locales..." -ForegroundColor Yellow
$acctRows = ""
$acctBad = 0
$acctWarn = 0
try {
    $localUsers = @()
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        $localUsers = Get-LocalUser -ErrorAction Stop
    } else {
        # Fallback: net user
        $out = net user 2>&1 | Where-Object { $_ -match "\S" -and $_ -notmatch "comando se completo" -and $_ -notmatch "---" }
        foreach ($ln in $out) { $localUsers += [PSCustomObject]@{ Name=$ln.Trim(); Enabled=$true; PasswordRequired=$null; PasswordLastSet=$null; Description="" } }
    }
    foreach ($u in $localUsers) {
        $name = if ($u.Name) { $u.Name } else { "$u" }
        $nameEsc = ConvertTo-HtmlEscaped $name
        $enabled = $u.Enabled
        if ($null -eq $enabled) { $enabled = $true }
        $pwdReq = $u.PasswordRequired
        $pwdLast = $null
        try { $pwdLast = $u.PasswordLastSet } catch {}
        $isGuest = ($name -like "*Guest*" -or $name -like "*Invitado*")
        $badge = "ok"
        $note = "OK"
        if ($isGuest -and $enabled -eq $true) { $badge = "bad"; $note = "Guest habilitado - deshabilitar"; $acctBad++ }
        elseif ($pwdReq -eq $false) { $badge = "bad"; $note = "Sin contrasena requerida"; $acctBad++ }
        elseif ($pwdLast -and ((Get-Date) - $pwdLast).TotalDays -gt 90) { $badge = "warn"; $note = "Contrasena >90 dias"; $acctWarn++ }
        elseif ($enabled -eq $false) { $badge = "warn"; $note = "Deshabilitada"; }
        else { $badge = "ok"; $note = "OK" }
        $enText = if ($enabled -eq $true -or $enabled -eq 1) { "Habilitada" } elseif ($enabled -eq $false -or $enabled -eq 0) { "Deshabilitada" } else { "N/D" }
        $pwdReqText = if ($null -eq $pwdReq) { "N/D" } elseif ($pwdReq) { "Si" } else { "No" }
        $lastText = if ($pwdLast) { $pwdLast.ToString("yyyy-MM-dd") } else { "N/D" }
        $acctRows += "<tr><td>$nameEsc</td><td>$enText</td><td>$pwdReqText</td><td>$lastText</td><td><span class='badge $badge'>$note</span></td></tr>"
    }
    # net accounts para politica general
    try {
        $na = net accounts 2>&1 | Out-String
        if ($na -match "Duraci.n m.xima de la contrase.a\s+(\d+)" -or $na -match "Maximum password age\s+(\d+)") {
            $maxAge = [int]$matches[1]
            if ($maxAge -gt 90 -or $maxAge -eq 2147483647) { $acctRows += "<tr><td colspan='5' class='text-muted'>Politica MaxPasswordAge: $maxAge dias (ilimitado o >90) - revisar GPO.</td></tr>"; $acctWarn++ }
        }
    } catch {}
    if (-not $acctRows) { $acctRows = "<tr><td colspan='5' class='text-muted'>No se detectaron cuentas locales.</td></tr>" }
} catch {
    $acctRows = "<tr><td colspan='5' class='text-muted'>No se pudo verificar cuentas: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
    $acctWarn = 1
}
$acctSummary = if ($acctBad -gt 0) { "<span class='badge bad'>$acctBad fallo(s)</span>" } elseif ($acctWarn -gt 0) { "<span class='badge warn'>$acctWarn aviso(s)</span>" } else { "<span class='badge ok'>OK</span>" }

# ----------------------------------------------------
# 8. LAPS / NLA / SMBv1 / COMPARTIDAS
# ----------------------------------------------------
Write-Host "[8/10] Verificando LAPS, NLA, SMBv1 y compartidas..." -ForegroundColor Yellow
$lapsRows = ""; $lapsBad = 0
$nlaRows = ""; $nlaBad = 0
$smbRows = ""; $smbBad = 0
$shareRows = ""; $shareBad = 0
try {
    # LAPS clasico y Windows LAPS
    $lapsClassic = $null; $lapsWin = $null; $lapsBackup = $null
    try { $lapsClassic = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name AdmPwdEnabled -ErrorAction Stop).AdmPwdEnabled } catch {}
    try { $lapsWin = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS" -Name BackupDirectory -ErrorAction Stop).BackupDirectory } catch {}
    try { $lapsBackup = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Policies\LAPS" -Name BackupDirectory -ErrorAction Stop).BackupDirectory } catch {}
    $lapsEnabled = ($lapsClassic -eq 1 -or $null -ne $lapsWin -or $null -ne $lapsBackup -or (Test-Path "C:\Windows\System32\AdmPwd.dll"))
    $lapsBadge = if ($lapsEnabled) { "ok" } else { "warn" }
    $lapsText = if ($lapsEnabled) { "Detectado (AdmPwd/LAPS)" } else { "No detectado - Revisar si aplica LAPS" }
    if (-not $lapsEnabled) { $lapsBad = 1 }
    $lapsRows = "<tr><td>LAPS</td><td>$lapsText</td><td><span class='badge $lapsBadge'>$(if($lapsEnabled){"OK"}else{"Revisar"})</span></td></tr>"
    # Tambien verificar si hay cuentas con LAPS aplicable (solo si domain joined)
    $isDomain = (Get-CimInstance Win32_ComputerSystem).PartOfDomain
    if ($isDomain -and -not $lapsEnabled) { $lapsRows += "<tr><td colspan='3' class='text-muted'>Equipo unido a dominio sin LAPS detectado - riesgo de reutilizacion de clave admin local.</td></tr>" }
} catch {
    $lapsRows = "<tr><td colspan='3' class='text-muted'>No se pudo verificar LAPS: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
try {
    $nla = $null; $deny = $null
    try { $nla = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -ErrorAction Stop).UserAuthentication } catch {}
    try { $deny = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections } catch {}
    $rdpEnabled = ($deny -eq 0)
    $nlaOk = ($nla -eq 1)
    if (-not $rdpEnabled) {
        $nlaRows = "<tr><td>RDP</td><td>Deshabilitado (fDenyTSConnections=1)</td><td><span class='badge ok'>OK</span></td></tr>"
    } else {
        $badge = if ($nlaOk) { "ok" } else { "bad" }
        $txt = if ($nlaOk) { "NLA requerido (UserAuthentication=1)" } else { "NLA NO requerido - activar" }
        if (-not $nlaOk) { $nlaBad = 1 }
        $nlaRows = "<tr><td>RDP NLA</td><td>$txt</td><td><span class='badge $badge'>$(if($nlaOk){"OK"}else{"Revisar"})</span></td></tr>"
    }
} catch {
    $nlaRows = "<tr><td colspan='3' class='text-muted'>No se pudo verificar NLA: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
try {
    $smb1 = $null
    if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
        $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol
    } else {
        try { $smb1 = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -ErrorAction Stop).SMB1 } catch { try { $smb1 = ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name Start -ErrorAction Stop).Start -ne 4) } catch {} }
    }
    $smbOn = ($smb1 -eq $true -or $smb1 -eq 1)
    $badge = if ($smbOn) { "bad" } else { "ok" }
    $txt = if ($smbOn) { "Habilitado - deshabilitar (vulnerable WannaCry)" } else { "Deshabilitado" }
    if ($smbOn) { $smbBad = 1 }
    $smbRows = "<tr><td>SMBv1</td><td>$txt</td><td><span class='badge $badge'>$(if($smbOn){"Revisar"}else{"OK"})</span></td></tr>"
} catch {
    $smbRows = "<tr><td colspan='3' class='text-muted'>No se pudo verificar SMBv1: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
try {
    if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
        $shares = Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -notin @("ADMIN$","C$","IPC$","PRINT$") }
        if ($shares) {
            foreach ($sh in $shares) {
                $access = Get-SmbShareAccess -Name $sh.Name -ErrorAction SilentlyContinue
                $everyone = $access | Where-Object { $_.AccountName -like "*Everyone*" -and $_.AccessRight -eq "Full" }
                $badge = if ($everyone) { "bad" } else { "ok" }
                $txt = if ($everyone) { "Everyone Full - Revisar" } else { "OK" }
                if ($everyone) { $shareBad++ }
                $shName = ConvertTo-HtmlEscaped $sh.Name
                $shPath = ConvertTo-HtmlEscaped $sh.Path
                $shareRows += "<tr><td>$shName</td><td>$shPath</td><td><span class='badge $badge'>$txt</span></td></tr>"
            }
        } else {
            $shareRows = "<tr><td colspan='3' class='text-ok'>Sin compartidas de usuario (solo ADMIN$/C$/IPC$).</td></tr>"
        }
    } else {
        $shareRows = "<tr><td colspan='3' class='text-muted'>Get-SmbShare no disponible.</td></tr>"
    }
} catch {
    $shareRows = "<tr><td colspan='3' class='text-muted'>No se pudo verificar compartidas: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}

# ----------------------------------------------------
# 9. HERRAMIENTAS REMOTAS + TRAZABILIDAD + EOL
# ----------------------------------------------------
Write-Host "[9/10] Verificando herramientas remotas, logs y EOL..." -ForegroundColor Yellow
$remoteRows = ""; $remoteBad = 0
$logRows = ""; $logBad = 0
$eolRows = ""; $eolBad = 0
try {
    $remoteChecks = @(
        @{ Name="AnyDesk"; Paths=@("C:\Program Files\AnyDesk\AnyDesk.exe","C:\Program Files (x86)\AnyDesk\AnyDesk.exe"); Service="AnyDesk" },
        @{ Name="TeamViewer"; Paths=@("C:\Program Files\TeamViewer\TeamViewer.exe","C:\Program Files (x86)\TeamViewer\TeamViewer_Service.exe"); Service="TeamViewer" },
        @{ Name="RustDesk"; Paths=@("C:\Program Files\RustDesk\rustdesk.exe","$env:APPDATA\RustDesk\rustdesk.exe"); Service="" },
        @{ Name="UltraVNC"; Paths=@("C:\Program Files\uvnc bvba\UltraVNC\vncviewer.exe"); Service="uvnc_service" },
        @{ Name="TightVNC"; Paths=@("C:\Program Files\TightVNC\tvnserver.exe"); Service="tvnserver" },
        @{ Name="Splashtop"; Paths=@("C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\SRServer.exe"); Service="SplashtopRemoteService" }
    )
    $foundRemote = @()
    foreach ($rc in $remoteChecks) {
        $foundPath = $null
        foreach ($pp in $rc.Paths) { if (Test-Path $pp) { $foundPath = $pp; break } }
        $svcFound = $false
        if ($rc.Service) { try { $svc = Get-Service -Name $rc.Service -ErrorAction Stop; if ($svc) { $svcFound = $true } } catch {} }
        if ($foundPath -or $svcFound) {
            $remoteBad++
            $val = if ($foundPath) { $foundPath } else { "Servicio $($rc.Service)" }
            $remoteRows += "<tr class='row-bad'><td>$(ConvertTo-HtmlEscaped $rc.Name)</td><td style='word-break:break-all;'>$(ConvertTo-HtmlEscaped $val)</td><td><span class='badge warn'>Revisar - autorizacion?</span></td></tr>"
        }
    }
    if (-not $remoteRows) { $remoteRows = "<tr><td colspan='3' class='text-ok'>No se detectaron herramientas remotas tipicas (AnyDesk/TeamViewer/RustDesk...).</td></tr>" }
} catch {
    $remoteRows = "<tr><td colspan='3' class='text-muted'>No se pudo verificar remoto: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
try {
    $logInfo = $null
    try { $logInfo = Get-WinEvent -ListLog Security -ErrorAction Stop } catch {}
    $maxMB = "N/D"; $ret = "N/D"; $enabled = "N/D"
    if ($logInfo) {
        $maxMB = [math]::Round($logInfo.MaximumSizeInBytes/1MB,0)
        $ret = $logInfo.LogMode
        $enabled = $logInfo.IsEnabled
    } else {
        try { $wev = wevtutil gl Security 2>&1 | Out-String; if ($wev -match "maxSize:\s*(\d+)") { $maxMB = [math]::Round([int]$matches[1]/1MB,0) } } catch {}
    }
    $logBadge = if ($maxMB -ne "N/D" -and [int]$maxMB -lt 20) { "warn" } else { "ok" }
    if ($logBadge -eq "warn") { $logBad = 1 }
    $maxEsc = ConvertTo-HtmlEscaped "$maxMB MB"
    $retEsc = ConvertTo-HtmlEscaped "$ret"
    $logRows += "<tr><td>Security log tamano max</td><td>$maxEsc</td><td><span class='badge $logBadge'>$(if($logBadge -eq 'ok'){'OK'}else{'Pequeno - ampliar a 64MB+'})</span></td></tr>"
    # W32Time
    $ntpSource = "N/D"; $ntpSync = "N/D"; $ntpBadge = "warn"
    try {
        $w32 = w32tm /query /status 2>&1 | Out-String
        if ($w32 -match "Source:\s*(.+)") { $ntpSource = $matches[1].Trim() }
        if ($w32 -match "Last Successful Sync Time:\s*(.+)") { $ntpSync = $matches[1].Trim() }
        $ntpBadge = if ($ntpSource -match "Local CMOS|No sync" -or $ntpSource -eq "N/D") { "warn" } else { "ok" }
        if ($ntpBadge -eq "warn") { $logBad++ }
    } catch {}
    $logRows += "<tr><td>NTP Fuente</td><td>$(ConvertTo-HtmlEscaped $ntpSource)</td><td><span class='badge $ntpBadge'>$(if($ntpBadge -eq 'ok'){'OK'}else{'Revisar - hora confiable requerida Art.10'})</span></td></tr>"
    $logRows += "<tr><td>Ultima sync</td><td>$(ConvertTo-HtmlEscaped $ntpSync)</td><td class='text-muted'>Evidencia forense requiere hora sincronizada</td></tr>"
} catch {
    $logRows = "<tr><td colspan='3' class='text-muted'>No se pudo verificar logs/NTP: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
try {
    $os = Get-CimInstance Win32_OperatingSystem
    $caption = $os.Caption
    $build = $os.BuildNumber
    $eolNote = "OK"
    $eolBadge = "ok"
    # Win10 EOL 14-oct-2025, sin ESU no recibe parches
    if ($caption -like "*Windows 10*") {
        $isPastEOL = (Get-Date) -gt (Get-Date "2025-10-14")
        if ($isPastEOL) {
            # Verificar ESU: clave HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ESU o ExtendedSecurityUpdates
            $hasESU = (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ESU") -or (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ESU -ErrorAction SilentlyContinue)
            if (-not $hasESU) { $eolNote = "Windows 10 sin soporte desde 2025-10-14 - migrar a Win11 o ESU"; $eolBadge = "bad"; $eolBad = 1 }
            else { $eolNote = "Windows 10 con ESU detectado - verificar vigencia"; $eolBadge = "warn" }
        } else {
            $eolNote = "Windows 10 - EOL 2025-10-14 proximo - planificar migracion"
            $eolBadge = "warn"
        }
    } elseif ($caption -like "*Windows 11*") {
        $eolNote = "Windows 11 vigente"; $eolBadge = "ok"
    } else {
        $eolNote = "SO no Windows 10/11 - verificar ciclo de vida"; $eolBadge = "warn"
    }
    $capEsc = ConvertTo-HtmlEscaped $caption
    $buildEsc = ConvertTo-HtmlEscaped "$build"
    $eolRows = "<tr><td>$capEsc</td><td>$buildEsc</td><td><span class='badge $eolBadge'>$eolNote</span></td></tr>"
} catch {
    $eolRows = "<tr><td colspan='3' class='text-muted'>No se pudo verificar EOL: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}

# ----------------------------------------------------
# 10. DEFENDER AVANZADO + BITLOCKER RECOVERY + SECUREBOOT/TPM
# ----------------------------------------------------
Write-Host "[10/10] Verificando Defender avanzado, BitLocker recovery y SecureBoot..." -ForegroundColor Yellow
$defAdvRows = ""; $defAdvBad = 0
$recRows = ""; $recBad = 0
$secRows = ""; $secBad = 0
try {
    if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
        $pref = Get-MpPreference -ErrorAction Stop
        $checks = @(
            @{ Label="Tamper Protection (IsTamperProtected)"; Value=(try{(Get-MpComputerStatus).IsTamperProtected}catch{$null}); Ok={ param($v) $v -eq $true } },
            @{ Label="Controlled Folder Access"; Value=$pref.EnableControlledFolderAccess; Ok={ param($v) $v -eq 1 } },
            @{ Label="Network Protection"; Value=$pref.EnableNetworkProtection; Ok={ param($v) $v -eq 1 } }
        )
        foreach ($chk in $checks) {
            $val = $chk.Value
            $ok = & $chk.Ok $val
            $badge = if ($ok) { "ok" } else { "warn" }
            $txt = if ($ok) { "OK" } else { "Revisar" }
            if (-not $ok) { $defAdvBad++ }
            $defAdvRows += "<tr><td>$(ConvertTo-HtmlEscaped $chk.Label)</td><td>$(ConvertTo-HtmlEscaped "$val")</td><td><span class='badge $badge'>$txt</span></td></tr>"
        }
        # ASR rules
        $asrIds = $pref.AttackSurfaceReductionRules_Ids
        $asrActs = $pref.AttackSurfaceReductionRules_Actions
        if ($asrIds -and $asrIds.Count -gt 0) {
            $active = 0
            for ($i=0; $i -lt $asrIds.Count; $i++) { if ($asrActs[$i] -eq 1) { $active++ } }
            $defAdvRows += "<tr><td>ASR Rules activas</td><td>$active de $($asrIds.Count)</td><td><span class='badge ok'>$active activas</span></td></tr>"
        } else {
            $defAdvRows += "<tr><td>ASR Rules</td><td>0</td><td><span class='badge warn'>Sin ASR - considerar GPO</span></td></tr>"; $defAdvBad++
        }
        # Threat detections recientes
        try {
            $threats = Get-MpThreatDetection -ErrorAction Stop | Select-Object -First 5
            if ($threats) {
                foreach ($th in $threats) {
                    $cat = ConvertTo-HtmlEscaped $th.ThreatID
                    $res = ConvertTo-HtmlEscaped "$($th.Resources)"
                    $defAdvRows += "<tr class='row-bad'><td>ThreatDetection</td><td>$cat - $res</td><td><span class='badge bad'>Incidente previo</span></td></tr>"
                    $defAdvBad++
                }
            } else {
                $defAdvRows += "<tr><td>ThreatDetection</td><td>Sin detecciones recientes</td><td><span class='badge ok'>OK</span></td></tr>"
            }
        } catch {}
    } else {
        $defAdvRows = "<tr><td colspan='3' class='text-muted'>Get-MpPreference no disponible.</td></tr>"
    }
} catch {
    $defAdvRows = "<tr><td colspan='3' class='text-muted'>No se pudo verificar Defender avanzado: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
try {
    # BitLocker Recovery: verificar que C: tenga RecoveryPassword protector y XTS-AES-256
    $recVols = @()
    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) { $recVols = Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object { $_.MountPoint -eq "C:" } }
    if ($recVols -and $recVols.Count -gt 0) {
        foreach ($rv in $recVols) {
            $hasRecovery = $false
            try { $hasRecovery = ($rv.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }).Count -gt 0 } catch {}
            $encMethod = $rv.EncryptionMethod
            # 3=AES128, 6=XTS-AES128, 7=XTS-AES256
            $methodTxt = "$encMethod"
            $methodBadge = if ($encMethod -eq 7) { "ok" } elseif ($encMethod -in @(3,6)) { "warn" } else { "warn" }
            $recBadge = if ($hasRecovery) { "ok" } else { "bad" }
            if (-not $hasRecovery) { $recBad++ }
            $recRows += "<tr><td>C: RecoveryPassword</td><td>$(if($hasRecovery){"Presente"}else{"AUSENTE - riesgo perdida datos"})</td><td><span class='badge $recBadge'>$(if($hasRecovery){"OK"}else{"Revisar"})</span></td></tr>"
            $recRows += "<tr><td>C: Metodo</td><td>$methodTxt (7=XTS-AES-256 recomendado)</td><td><span class='badge $methodBadge'>$(if($encMethod -eq 7){"OK"}else{"Revisar"})</span></td></tr>"
        }
    } else {
        $recRows = "<tr><td colspan='3' class='text-muted'>No se pudo verificar Recovery (Get-BitLockerVolume no disponible o sin Admin).</td></tr>"
    }
} catch {
    $recRows = "<tr><td colspan='3' class='text-muted'>Error Recovery check: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
try {
    $secChecks = @()
    # SecureBoot
    $sb = $null; $sbOk = $false
    try { $sb = Confirm-SecureBootUEFI -ErrorAction Stop; $sbOk = $sb } catch { $sb = "No soportado/BIOS Legacy ($($_.Exception.Message))" }
    $sbBadge = if ($sbOk -eq $true) { "ok" } else { "warn" }
    if ($sbOk -ne $true) { $secBad++ }
    $secChecks += "<tr><td>SecureBoot</td><td>$(ConvertTo-HtmlEscaped "$sb")</td><td><span class='badge $sbBadge'>$(if($sbOk -eq $true){"OK"}else{"Revisar"})</span></td></tr>"
    # TPM
    $tpmPresent = "N/D"; $tpmBadge = "warn"
    try { $tpm = Get-Tpm -ErrorAction Stop; $tpmPresent = "Present=$($tpm.TpmPresent) Ready=$($tpm.TpmReady) Enabled=$($tpm.TpmEnabled)"; $tpmBadge = if ($tpm.TpmReady) { "ok" } else { "warn" }; if (-not $tpm.TpmReady) { $secBad++ } } catch { $tpmPresent = "No disponible: $($_.Exception.Message)" }
    $secChecks += "<tr><td>TPM</td><td>$(ConvertTo-HtmlEscaped $tpmPresent)</td><td><span class='badge $tpmBadge'>$(if($tpmBadge -eq 'ok'){'OK'}else{'Revisar'})</span></td></tr>"
    # VBS / DeviceGuard
    try { $dg = Get-CimInstance Win32_DeviceGuard -ErrorAction Stop -Namespace root\Microsoft\Windows\DeviceGuard; $vbs = $dg.VirtualizationBasedSecurityStatus; $vbsBadge = if ($vbs -eq 2) { "ok" } else { "warn" }; if ($vbs -ne 2) { $secBad++ }; $secChecks += "<tr><td>VBS</td><td>Status=$vbs (2=Running)</td><td><span class='badge $vbsBadge'>$(if($vbs -eq 2){'OK'}else{'Revisar'})</span></td></tr>" } catch {}
    $secRows = ($secChecks -join "")
    if (-not $secRows) { $secRows = "<tr><td colspan='3' class='text-muted'>No se pudo verificar SecureBoot/TPM/VBS.</td></tr>" }
} catch {
    $secRows = "<tr><td colspan='3' class='text-muted'>Error SecureBoot/TPM: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}

# Resumen global LOPDP (ahora con controles extendidos)
$extraBad = $screenBad + $acctBad + $lapsBad + $nlaBad + $smbBad + $shareBad + $remoteBad + $logBad + $eolBad + $defAdvBad + $recBad + $secBad
$totalBad = $bitlockerBad + $listenBad + $fwBad + $avBad + $adminBad + $extraBad
$globalBadge = if ($totalBad -eq 0) { "ok" } elseif ($totalBad -le 2) { "warn" } else { "bad" }
$globalText = if ($totalBad -eq 0) { "Cumple controles basicos LOPDP" } elseif ($totalBad -le 2) { "$totalBad hallazgo(s) - correccion recomendada" } else { "$totalBad hallazgos criticos - accion inmediata" }

# ----------------------------------------------------
# HTML
# ----------------------------------------------------
$computerEsc = ConvertTo-HtmlEscaped $ComputerName

$htmlContent = @"
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Auditoria LOPDP Endpoint - $computerEsc</title>
    <style>
        :root {
            --bg: #0f172a; --card-bg: #1e293b; --card-border: #334155;
            --text-main: #f8fafc; --text-muted: #94a3b8; --accent-blue: #38bdf8;
            --ok-color: #22c55e; --warn-color: #eab308; --bad-color: #ef4444;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        body { background-color: var(--bg); color: var(--text-main); padding: 24px; line-height: 1.5; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--card-border); padding-bottom: 16px; margin-bottom: 24px; }
        .header h1 { font-size: 22px; color: var(--accent-blue); }
        .header p { color: var(--text-muted); font-size: 13px; }
        .card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 8px; padding: 20px; margin-bottom: 24px; }
        .card h3 { color: var(--accent-blue); margin-bottom: 12px; font-size: 17px; border-bottom: 1px solid var(--card-border); padding-bottom: 8px; }
        .card h4 { color: var(--text-muted); font-size: 13px; margin-top: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
        th { text-align: left; background: rgba(15, 23, 42, 0.8); color: var(--text-muted); padding: 10px; border-bottom: 1px solid var(--card-border); }
        td { padding: 10px; border-bottom: 1px solid var(--card-border); vertical-align: top; }
        tr:hover { background: rgba(255,255,255,0.02); }
        tr.row-bad { background: rgba(239,68,68,0.10); }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; white-space: nowrap; }
        .badge.ok { background: rgba(34,197,94,0.2); color: var(--ok-color); border: 1px solid var(--ok-color); }
        .badge.warn { background: rgba(234,179,8,0.2); color: var(--warn-color); border: 1px solid var(--warn-color); }
        .badge.bad { background: rgba(239,68,68,0.2); color: var(--bad-color); border: 1px solid var(--bad-color); }
        .text-muted { color: var(--text-muted); }
        .text-ok { color: var(--ok-color); }
        .grid-summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; margin-bottom: 24px; }
        .summary-card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 8px; padding: 14px; text-align: center; }
        .summary-card .num { font-size: 22px; font-weight: bold; }
        .mitig { background: rgba(56,189,248,0.08); border: 1px dashed var(--accent-blue); border-radius: 6px; padding: 10px; margin-top: 12px; font-size: 12px; color: var(--text-muted); }
        .footer { text-align: center; color: var(--text-muted); font-size: 11px; margin-top: 30px; }
        code { background: rgba(255,255,255,0.08); padding: 2px 6px; border-radius: 4px; font-size: 12px; }
    </style>
</head>
<body>

    <div class="header">
        <div>
            <h1>Auditoria de Seguridad Endpoint - LOPDP Art.10 y 38</h1>
            <p>Equipo: <strong>$computerEsc</strong> | Fecha: $ReportDate | Elevado: $(if($isElevated){"SI"}else{"NO - algunos controles no verificados"})</p>
        </div>
        <div><span class="badge $globalBadge" style="font-size:14px;">$globalText</span></div>
    </div>

    <div class="grid-summary">
        <div class="summary-card"><div class="num">$bitlockerSummary</div><div class="text-muted" style="font-size:12px;">Cifrado BitLocker</div></div>
        <div class="summary-card"><div class="num">$listenSummary</div><div class="text-muted" style="font-size:12px;">Puertos expuestos</div></div>
        <div class="summary-card"><div class="num">$fwSummary</div><div class="text-muted" style="font-size:12px;">Firewall</div></div>
        <div class="summary-card"><div class="num">$avSummary</div><div class="text-muted" style="font-size:12px;">Antivirus</div></div>
        <div class="summary-card"><div class="num">$adminSummary</div><div class="text-muted" style="font-size:12px;">Admins locales</div></div>
    </div>

    <!-- 1. BitLocker -->
    <div class="card">
        <h3>1. Cifrado de disco (BitLocker) - Riesgo: robo de laptop con datos de clientes</h3>
        <p class="text-muted" style="font-size:12px;">LOPDP Art.38 exige medidas tecnicas contra acceso no autorizado. Sin BitLocker, basta extraer el disco y leerlo en otro PC. Mitigacion: activar BitLocker en C: y unidades de datos, guardar clave en AD/AzureAD.</p>
        <table>
            <thead><tr><th>Unidad</th><th>Proteccion</th><th>Cifrado</th><th>Protectores</th></tr></thead>
            <tbody>$bitlockerRows</tbody>
        </table>
        <div class="mitig"><strong>Mitigacion:</strong> <code>Enable-BitLocker -MountPoint C: -RecoveryPasswordProtector</code> + backup a AD. Verificar con <code>manage-bde -status</code>.</div>
    </div>

    <!-- 2. Puertos -->
    <div class="card">
        <h3>2. Puertos TCP en escucha (superficie de ataque) $listenSummary</h3>
        <p class="text-muted" style="font-size:12px;">Riesgo: RDP 3389 y SMB 445 expuestos permiten fuerza bruta y ransomware lateral (EternalBlue/WannaCry). Mitigacion: desactivar RDP si no se usa o restringir por VPN/Firewall; cerrar 445/135 si no hay compartidos.</p>
        <table>
            <thead><tr><th>Bind</th><th>Puerto / Servicio</th><th>Proceso</th><th>Accion</th></tr></thead>
            <tbody>$listenRows</tbody>
        </table>
        <div class="mitig"><strong>Mitigacion:</strong> <code>Set-NetFirewallRule -DisplayName "Remote Desktop*" -Enabled False</code> o Firewall con regla solo VPN. Auditar con <code>Get-NetTCPConnection -State Listen</code>.</div>
    </div>

    <!-- 3. Firewall -->
    <div class="card">
        <h3>3. Firewall de Windows $fwSummary</h3>
        <p class="text-muted" style="font-size:12px;">Riesgo: perfiles desactivados por usuario/malware dejan SMB/RDP sin filtro. Mitigacion: forzar via GPO que Domain/Private/Public esten Activos y Bloqueen entrante.</p>
        <table>
            <thead><tr><th>Perfil</th><th>Estado</th><th>Accion por defecto entrante</th></tr></thead>
            <tbody>$fwRows</tbody>
        </table>
        <div class="mitig"><strong>Mitigacion:</strong> <code>Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block</code>.</div>
    </div>

    <!-- 4. AV -->
    <div class="card">
        <h3>4. Antivirus / Defender $avSummary</h3>
        <p class="text-muted" style="font-size:12px;">Riesgo: proteccion desactivada para instalar pirateria o por malware. Mitigacion: monitorear AMService y firmas &lt;7 dias via Intune/EDR.</p>
        <table>
            <thead><tr><th>Componente</th><th>Estado</th><th>Nota</th></tr></thead>
            <tbody>$avRows</tbody>
        </table>
        <div class="mitig"><strong>Mitigacion:</strong> <code>Update-MpSignature</code> + GPO Tamper Protection. Si usa EDR tercero, verificar su consola.</div>
    </div>

    <!-- 5. Admins -->
    <div class="card">
        <h3>5. Cuentas con privilegios de Administrador local $adminSummary</h3>
        <p class="text-muted" style="font-size:12px;">Riesgo: usuario de finanzas navegando como Admin - el malware hereda privilegios y roba todo. Mitigacion: principio de menor privilegio (usuarios estandar; solo TI es Admin local, via LAPS).</p>
        <table>
            <thead><tr><th>Cuenta</th><th>Tipo</th><th>Origen</th><th>Evaluacion</th></tr></thead>
            <tbody>$adminRows</tbody>
        </table>
        <div class="mitig"><strong>Mitigacion:</strong> <code>Remove-LocalGroupMember -Group Administradores -Member "dominio\usuario"</code> + GPO Restricted Groups / LAPS. Ideal: max 2 admins locales.</div>
    </div>

    <!-- 6. Bloqueo pantalla -->
    <div class="card">
        <h3>6. Bloqueo de pantalla por inactividad $screenSummary</h3>
        <p class="text-muted" style="font-size:12px;">Riesgo: portatil contable sin bloqueo = acceso fisico a datos si se deja desatendido. LOPDP exige bloqueo automatico.</p>
        <table>
            <thead><tr><th>Item</th><th>Valor</th><th>Esperado</th><th>Estado</th></tr></thead>
            <tbody>$screenRows</tbody>
        </table>
        <div class="mitig"><strong>Mitigacion:</strong> GPO <code>ScreenSaveTimeOut 600</code> + <code>ScreenSaverIsSecure 1</code> + <code>InactivityTimeoutSecs 600</code></div>
    </div>

    <!-- 7. Salud cuentas -->
    <div class="card">
        <h3>7. Salud de cuentas locales $acctSummary</h3>
        <p class="text-muted" style="font-size:12px;">Contrasena vacia, Guest habilitado o contrasenas >90 dias = incumplimiento.</p>
        <table>
            <thead><tr><th>Cuenta</th><th>Estado</th><th>Pwd Requerida</th><th>Ultimo cambio</th><th>Evaluacion</th></tr></thead>
            <tbody>$acctRows</tbody>
        </table>
    </div>

    <!-- 8. LAPS / NLA / SMBv1 / Shares -->
    <div class="card">
        <h3>8. LAPS / NLA / SMBv1 / Compartidas</h3>
        <h4>LAPS</h4>
        <table><thead><tr><th>Control</th><th>Valor</th><th>Estado</th></tr></thead><tbody>$lapsRows</tbody></table>
        <h4>RDP NLA</h4>
        <table><thead><tr><th>Control</th><th>Valor</th><th>Estado</th></tr></thead><tbody>$nlaRows</tbody></table>
        <h4>SMBv1</h4>
        <table><thead><tr><th>Control</th><th>Valor</th><th>Estado</th></tr></thead><tbody>$smbRows</tbody></table>
        <h4>Compartidas con Everyone Full</h4>
        <table><thead><tr><th>Share</th><th>Ruta</th><th>Estado</th></tr></thead><tbody>$shareRows</tbody></table>
    </div>

    <!-- 9. Remote tools / Logs / EOL -->
    <div class="card">
        <h3>9. Herramientas remotas / Trazabilidad / EOL</h3>
        <h4>Herramientas de acceso remoto</h4>
        <table><thead><tr><th>Tool</th><th>Evidencia</th><th>Estado</th></tr></thead><tbody>$remoteRows</tbody></table>
        <h4>Retencion de log Security + NTP</h4>
        <table><thead><tr><th>Item</th><th>Valor</th><th>Estado</th></tr></thead><tbody>$logRows</tbody></table>
        <h4>Fin de soporte (EOL)</h4>
        <table><thead><tr><th>SO</th><th>Build</th><th>Estado</th></tr></thead><tbody>$eolRows</tbody></table>
    </div>

    <!-- 10. Defender avanzado / Recovery / SecureBoot -->
    <div class="card">
        <h3>10. Defender avanzado / BitLocker Recovery / SecureBoot+TPM</h3>
        <h4>Defender CFA / ASR / Threats</h4>
        <table><thead><tr><th>Item</th><th>Valor</th><th>Estado</th></tr></thead><tbody>$defAdvRows</tbody></table>
        <h4>BitLocker Recovery (C:)</h4>
        <table><thead><tr><th>Item</th><th>Valor</th><th>Estado</th></tr></thead><tbody>$recRows</tbody></table>
        <h4>SecureBoot / TPM / VBS</h4>
        <table><thead><tr><th>Item</th><th>Valor</th><th>Estado</th></tr></thead><tbody>$secRows</tbody></table>
    </div>

    <div class="footer">
        Reporte LOPDP generado automaticamente | Soporte Tecnico e Infraestructura | LOPDP Art.10 y 38 - Seguridad de Datos Personales - Ecuador
    </div>

</body>
</html>
"@

try {
    [System.IO.File]::WriteAllText($OutputFile, $htmlContent, [System.Text.Encoding]::UTF8)
} catch {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $htmlContent | Out-File -FilePath $OutputFile -Encoding utf8BOM -Force
    } else {
        $htmlContent | Out-File -FilePath $OutputFile -Encoding utf8 -Force
    }
}
Write-Host "`n==================================================" -ForegroundColor Green
Write-Host " Reporte LOPDP generado en:" -ForegroundColor Green
Write-Host " $OutputFile" -ForegroundColor Cyan
Write-Host " Hallazgos criticos: $totalBad" -ForegroundColor $(if($totalBad -eq 0){"Green"}else{"Red"})
Write-Host "==================================================" -ForegroundColor Green
Start-Process $OutputFile
"""
dst.write_text(content, encoding="utf-8")
print("Wrote", len(content.splitlines()), "lines")
