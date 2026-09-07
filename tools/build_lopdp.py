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
Write-Host "[1/5] Verificando cifrado de disco (BitLocker)..." -ForegroundColor Yellow
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
Write-Host "[2/5] Auditando puertos en escucha (RDP/SMB/RPC...)" -ForegroundColor Yellow
$riskPorts = @(3389,445,135,21,22,23,80,443,5985,5986)
$riskNames = @{ 3389="RDP"; 445="SMB"; 135="RPC"; 21="FTP"; 22="SSH"; 23="Telnet"; 80="HTTP"; 443="HTTPS"; 5985="WinRM-HTTP"; 5986="WinRM-HTTPS" }
$listenRows = ""
$listenBad = 0
try {
    $listens = Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { ($_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::' -or $_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress.StartsWith("0.")) -and ($riskPorts -contains $_.LocalPort) }
    # Nota: en algunos builds LocalAddress viene como 0.0.0.0 o ::, filtramos por puerto
    # Si el filtro anterior deja todo vacio por formato, reintentar solo por puerto + Listen
    if (-not $listens -or $listens.Count -eq 0) {
        $listens = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $riskPorts -contains $_.LocalPort }
        # Filtrar solo los que escuchan en todas las interfaces
        $listens = $listens | Where-Object { $_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::' -or $_.LocalAddress -eq '0.0.0.0' }
    }
    if ($listens -and $listens.Count -gt 0) {
        $listenBad = $listens.Count
        foreach ($ln in $listens) {
            $port = $ln.LocalPort
            $svc = if ($riskNames.ContainsKey($port)) { $riskNames[$port] } else { "Servicio $port" }
            $addr = ConvertTo-HtmlEscaped $ln.LocalAddress
            $proc = ""
            try { $proc = (Get-Process -Id $ln.OwningProcess -ErrorAction Stop).ProcessName } catch { $proc = "PID $($ln.OwningProcess)" }
            $procEsc = ConvertTo-HtmlEscaped $proc
            $svcEsc = ConvertTo-HtmlEscaped $svc
            $listenRows += "<tr class='row-bad'><td>$addr</td><td><span class='badge bad'>$port</span> $svcEsc</td><td>$procEsc ($($ln.OwningProcess))</td><td>Expuesto a toda la red local - Cerrar o restringir por Firewall/VPN</td></tr>"
        }
    } else {
        $listenRows = "<tr><td colspan='4' class='text-ok'>Ningun puerto critico (3389/445/135...) expuesto en 0.0.0.0/:: (correcto).</td></tr>"
    }
} catch {
    # Fallback netstat para sistemas sin Get-NetTCPConnection
    try {
        $ns = netstat -ano 2>&1 | Select-String "LISTENING"
        $found = @()
        foreach ($line in $ns) {
            foreach ($rp in $riskPorts) {
                if ($line -match ":$rp\s") { $found += $line.Line.Trim() }
            }
        }
        if ($found.Count -gt 0) {
            $listenBad = $found.Count
            foreach ($f in ($found | Select-Object -First 20)) {
                $listenRows += "<tr class='row-bad'><td colspan='4'>$(ConvertTo-HtmlEscaped $f) <span class='badge bad'>Revisar</span></td></tr>"
            }
        } else {
            $listenRows = "<tr><td colspan='4' class='text-ok'>netstat no reporta puertos criticos en escucha.</td></tr>"
        }
    } catch {
        $listenRows = "<tr><td colspan='4' class='text-muted'>No se pudo auditar puertos: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
    }
}
$listenSummary = if ($listenBad -gt 0) { "<span class='badge bad'>$listenBad puerto(s) expuesto(s)</span>" } else { "<span class='badge ok'>Sin exposicion critica</span>" }

# ----------------------------------------------------
# 3. FIREWALL DE WINDOWS
# ----------------------------------------------------
Write-Host "[3/5] Verificando Firewall de Windows..." -ForegroundColor Yellow
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
Write-Host "[4/5] Verificando Antivirus/Defender..." -ForegroundColor Yellow
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
Write-Host "[5/5] Auditando cuentas con privilegios de Administrador local..." -ForegroundColor Yellow
$adminRows = ""
$adminCount = 0
$adminBad = 0
try {
    # SID S-1-5-32-544 = Administradores, independiente de idioma (Administrators/Administradores)
    $members = Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop
    $adminCount = $members.Count
    foreach ($m in $members) {
        $name = ConvertTo-HtmlEscaped $m.Name
        $src = ConvertTo-HtmlEscaped $m.PrincipalSource
        $objClass = ConvertTo-HtmlEscaped $m.ObjectClass
        # Heuristica: si es usuario local y no es Administrator/Administrateur, puede ser exceso de privilegios
        $isBuiltIn = ($name -like "*Administrator*" -or $name -like "*Administrador*" -or $src -eq "ActiveDirectory")
        $badge = if ($isBuiltIn) { "ok" } else { "warn" }
        # Si hay mas de 2 admins no built-in, marcar bad
        if (-not $isBuiltIn -and $adminCount -gt 3) { $badge = "bad"; $adminBad++ }
        $adminRows += "<tr><td>$name</td><td>$objClass</td><td>$src</td><td><span class='badge $badge'>$(if($badge -eq 'ok'){'Sistema'}else{'Revisar'})</span></td></tr>"
    }
    if ($adminCount -eq 0) {
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

# Resumen global LOPDP
$totalBad = $bitlockerBad + $listenBad + $fwBad + $avBad + $adminBad
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
dst.write_text(content, encoding='utf-8')
print(f"Wrote {len(content.splitlines())} lines, non-ascii: {[c for c in content if ord(c)>127][:10]}")
