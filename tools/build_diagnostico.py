import pathlib
dst = pathlib.Path(r"C:\Users\ASUS\workspace\WindowsDiagnosis\Diagnostico-PC-HTML.ps1")
content = r"""<#
.SYNOPSIS
    Script de Diagnostico Integral para Windows con Reporte HTML.
.DESCRIPTION
    Recopila estado del sistema, procesador, memoria RAM, salud de bateria, discos S.M.A.R.T.,
    volumenes logicos, GPU, red, Defender, Windows Update, controladores con fallos y eventos
    criticos del sistema en un reporte HTML interactivo. Sin dependencias externas ni instalacion.
.NOTES
    Requiere PowerShell 5.1+ (no usa sintaxis exclusiva de PowerShell 7).
    Si al copiarlo desde otra PC/USB Windows lo bloquea con advertencia de seguridad,
    ejecuta primero: Unblock-File -Path .\Diagnostico-PC-HTML.ps1
    Si la politica de ejecucion lo impide, corre PowerShell asi (solo para este proceso):
    powershell -ExecutionPolicy Bypass -File .\Diagnostico-PC-HTML.ps1
#>

#Requires -Version 5.1

param(
    [string]$OutputPath = "",
    [switch]$NoOpen,
    [int]$Days = 2
)

# --- GOTCHAS DE EJECUCION (entornos endurecidos) ---
if ($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage") {
    Write-Host "ADVERTENCIA: LanguageMode=$($ExecutionContext.SessionState.LanguageMode) (no FullLanguage). Algunas secciones fallaran. Ejecuta en host no endurecido o firma el script." -ForegroundColor Yellow
}
try {
    $pol = Get-ExecutionPolicy -List -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq "MachinePolicy" }
    if ($pol -and $pol.ExecutionPolicy -ne "Undefined" -and $pol.ExecutionPolicy -ne "Bypass" -and $pol.ExecutionPolicy -ne "Unrestricted") {
        Write-Host "ADVERTENCIA: MachinePolicy=$($pol.ExecutionPolicy) via GPO. Bypass no aplica. Firma el script o usa GPO de excepcion." -ForegroundColor Yellow
    }
} catch {}
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    $sysNative = "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe"
    $sys64 = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $target = if (Test-Path $sysNative) { $sysNative } else { $sys64 }
    Write-Host "AVISO: Ejecutandose en PowerShell 32-bit en OS 64-bit. Relanzando en 64-bit..." -ForegroundColor Yellow
    try {
        $args = @("-ExecutionPolicy","Bypass","-File", $PSCommandPath)
        if ($OutputPath) { $args += @("-OutputPath", $OutputPath) }
        if ($NoOpen) { $args += "-NoOpen" }
        & $target @args
        exit $LASTEXITCODE
    } catch { Write-Host "No se pudo relanzar en 64-bit: $($_.Exception.Message)" -ForegroundColor Yellow }
}



function Test-PendingReboot {
    $reasons = @()
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") { $reasons += "CBS RebootPending" }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") { $reasons += "WU RebootRequired" }
    try { if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction Stop).PendingFileRenameOperations) { $reasons += "PendingFileRenameOperations" } } catch {}
    return $reasons
}
function Get-DesktopPathSafe {
    $desktop = [Environment]::GetFolderPath("Desktop")
    if (-not $desktop -or -not (Test-Path $desktop)) { $desktop = "$env:USERPROFILE\Desktop" }
    $isOneDrive = ($desktop -like "*OneDrive*")
    return @{ Path=$desktop; IsOneDrive=$isOneDrive }
}
function Get-BatteryViaWmi {
    try {
        $static = Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData -ErrorAction Stop | Select-Object -First 1
        $full = Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity -ErrorAction Stop | Select-Object -First 1
        if ($static -and $full -and $static.DesignedCapacity -gt 0) {
            return @{ Design=$static.DesignedCapacity; Full=$full.FullChargedCapacity }
        }
    } catch {}
    return $null
}
function Invoke-WingetSafe {
    param([int]$TimeoutSec=25)
    try {
        $job = Start-Job -ScriptBlock { winget upgrade --include-unknown --accept-source-agreements --disable-interactivity --source winget 2>&1 | Out-String } -ErrorAction Stop
        $completed = Wait-Job $job -Timeout $TimeoutSec
        if ($completed) {
            $out = Receive-Job $job -ErrorAction SilentlyContinue
            Remove-Job $job -Force -ErrorAction SilentlyContinue
            return $out
        } else {
            Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
            return "Winget timeout ${TimeoutSec}s - se omite (posible prompt msstore)"
        }
    } catch { return "Winget no disponible: $($_.Exception.Message)" }
}
function Get-PendingRebootHtml {
    $reasons = Test-PendingReboot
    if ($reasons.Count -gt 0) {
        $txt = ($reasons -join ", ")
        return "<tr class='row-bad'><td>Reboot pendiente</td><td>$(ConvertTo-HtmlEscaped $txt)</td><td><span class='badge bad'>Reinicio requerido</span> - causa #1 de lentitud</td></tr>"
    } else {
        return "<tr><td>Reboot pendiente</td><td>Ninguno</td><td><span class='badge ok'>OK</span></td></tr>"
    }
}


$ErrorActionPreference = "SilentlyContinue"

# Helper para escapar texto dinamico antes de inyectarlo en HTML.
function ConvertTo-HtmlEscaped {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

# Helper para Get-Counter con fallback en ingles/espanol (contadores localizados)
function Get-CounterSafe {
    param([string[]]$Paths)
    foreach ($p in $Paths) {
        try {
            $v = (Get-Counter -Counter $p -ErrorAction Stop).CounterSamples.CookedValue
            if ($null -ne $v) { return $v }
        } catch {}
    }
    return $null
}

# La mayoria de estas consultas (CIM, PnpDevice, PhysicalDisk, powercfg, WinEvent de
# System/Application) NO requieren Administrador en un Windows estandar. Solo se avisa
# aqui para que, si algo sale vacio mas abajo, sepas que puede ser por permisos y no
# porque "todo este bien".
$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isElevated) {
    Write-Host "Nota: no se esta ejecutando como Administrador. La mayoria de las secciones funcionan igual;" -ForegroundColor DarkGray
    Write-Host "si el Visor de Eventos aparece vacio por error de permisos, se indicara explicitamente." -ForegroundColor DarkGray
}
$ReportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ComputerName = $env:COMPUTERNAME
$desktopInfo = Get-DesktopPathSafe
$desktopPath = $desktopInfo.Path
$oneDriveWarn = $desktopInfo.IsOneDrive
if ($OutputPath) { $OutputFile = $OutputPath } else { $OutputFile = Join-Path $desktopPath ("Diagnostico_${ComputerName}_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".html") }

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " Generando Diagnostico Integral para $ComputerName..." -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# ----------------------------------------------------
# 1. INFORMACION DEL SISTEMA Y CPU
# ----------------------------------------------------
Write-Host "[1/12] Analizando Sistema y Procesador..." -ForegroundColor Yellow
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$cpuList = Get-CimInstance Win32_Processor

$osName = $os.Caption
$osVersion = $os.Version
$uptime = (Get-Date) - $os.LastBootUpTime
$uptimeStr = "$($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"

$cpuName = $cpuList[0].Name
$cpuCores = $cpuList[0].NumberOfCores
$cpuLogical = $cpuList[0].NumberOfLogicalProcessors
$cpuLoad = ($cpuList | Measure-Object -Property LoadPercentage -Average).Average

# Win32_Processor.LoadPercentage es opcional: en VMs o ciertos fabricantes viene $null.
# Windows tampoco tiene "load average" como Linux; es solo una foto instantanea.
if ($null -eq $cpuLoad) {
    $v = Get-CounterSafe @('\Processor(_Total)\% Processor Time','\Procesador(_Total)\% de tiempo de procesador')
    if ($null -ne $v) { $cpuLoad = [math]::Round($v,1) } else { $cpuLoad = 0 }
} else {
    $cpuLoad = [math]::Round($cpuLoad,1)
}

# ----------------------------------------------------
# 2. MEMORIA RAM
# ----------------------------------------------------
Write-Host "[2/12] Analizando Memoria RAM..." -ForegroundColor Yellow
$totalRamGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
$freeRamGB  = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
$usedRamGB  = [math]::Round($totalRamGB - $freeRamGB, 2)
$ramPct     = [math]::Round(($usedRamGB / $totalRamGB) * 100, 1)

# FreePhysicalMemory NO equivale a "disponible": Windows cachea agresivamente en RAM
# (similar al buff/cache de Linux). "Available MBytes" si descuenta esa cache reclamable.
$ramAvailableMB = Get-CounterSafe @('\Memory\Available MBytes','\Memoria\Mbytes disponibles')
if ($null -ne $ramAvailableMB) {
    $ramAvailableGB = [math]::Round($ramAvailableMB / 1024, 2)
} else {
    $ramAvailableGB = $freeRamGB
}

$ramModules = Get-CimInstance Win32_PhysicalMemory
$ramTableRows = ""
if ($ramModules) {
    foreach ($mod in $ramModules) {
        $cap = [math]::Round($mod.Capacity / 1GB, 2)
        $loc = ConvertTo-HtmlEscaped $mod.DeviceLocator
        $man = ConvertTo-HtmlEscaped $mod.Manufacturer
        $ramTableRows += "<tr><td>$loc</td><td>$cap GB</td><td>$($mod.Speed) MHz</td><td>$man</td></tr>"
    }
} else {
    $ramTableRows = "<tr><td colspan='4'>No se pudo obtener informacion detallada de los modulos.</td></tr>"
}

# ----------------------------------------------------
# 3. CONTROLADORES
# ----------------------------------------------------
Write-Host "[3/12] Verificando Controladores..." -ForegroundColor Yellow
$badDrivers = Get-PnpDevice | Where-Object { $_.Status -ne "OK" -and $_.ConfigManagerErrorCode -ne 0 }
$driversRows = ""
if ($badDrivers) {
    foreach ($drv in $badDrivers) {
        $drvName  = ConvertTo-HtmlEscaped $drv.FriendlyName
        $drvClass = ConvertTo-HtmlEscaped $drv.Class
        $driversRows += "<tr class='row-bad'><td>$drvName</td><td>$drvClass</td><td><span class='badge bad'>Error $($drv.ConfigManagerErrorCode)</span></td></tr>"
    }
} else {
    $driversRows = "<tr><td colspan='3' class='text-ok'>Todos los controladores y dispositivos funcionan correctamente.</td></tr>"
}

# ----------------------------------------------------
# 4. SALUD DE BATERIA
# ----------------------------------------------------
Write-Host "[4/12] Analizando Bateria..." -ForegroundColor Yellow
$battery = Get-CimInstance Win32_Battery
$batteryHtml = ""
if ($battery) {
    $tempReport = "$env:TEMP\batt_report_temp.html"
    powercfg /batteryreport /output $tempReport | Out-Null
    $designCap = $null
    $fullCap = $null
    if (Test-Path $tempReport) {
        $content = Get-Content $tempReport -Raw
        if ($content -match 'DESIGN CAPACITY</span></td><td>\s*([\d,]+)\s*mWh') { $designCap = [double]($matches[1] -replace ',','') }
        if ($content -match 'FULL CHARGE CAPACITY</span></td><td>\s*([\d,]+)\s*mWh') { $fullCap = [double]($matches[1] -replace ',','') }
        Remove-Item $tempReport -ErrorAction SilentlyContinue
    }
    if ($designCap -and $fullCap -and $designCap -gt 0) {
        $wearPct = [math]::Round((1 - ($fullCap / $designCap)) * 100, 1)
        $healthPct = [math]::Round(($fullCap / $designCap) * 100, 1)
        $badgeClass = if ($wearPct -gt 35) { "bad" } elseif ($wearPct -gt 20) { "warn" } else { "ok" }
        $batteryHtml = @"
        <div class="card">
            <h3>Estado de Bateria</h3>
            <div class="metrics-grid">
                <div class="metric-box">
                    <span class="metric-label">Capacidad de Diseno</span>
                    <span class="metric-value">$designCap mWh</span>
                </div>
                <div class="metric-box">
                    <span class="metric-label">Carga Maxima Actual</span>
                    <span class="metric-value">$fullCap mWh</span>
                </div>
                <div class="metric-box">
                    <span class="metric-label">Salud Residual</span>
                    <span class="metric-value">$healthPct %</span>
                </div>
                <div class="metric-box">
                    <span class="metric-label">Nivel de Desgaste</span>
                    <span class="badge $badgeClass">$wearPct %</span>
                </div>
            </div>
        </div>
"@
    } else {
        $batteryHtml = "<div class='card'><h3>Estado de Bateria</h3><p>Bateria presente, pero no se pudo generar el calculo preciso de desgaste.</p></div>"
    }
} else {
    $batteryHtml = "<div class='card'><h3>Estado de Bateria</h3><p class='text-muted'>Equipo de escritorio (sin bateria instalada).</p></div>"
}

# ----------------------------------------------------
# 5. DISCOS FISICOS (S.M.A.R.T.)
# ----------------------------------------------------
Write-Host "[5/12] Verificando Discos y Almacenamiento..." -ForegroundColor Yellow
$disks = Get-PhysicalDisk
$diskRows = ""
if ($disks) {
    foreach ($d in $disks) {
        $sizeGB = [math]::Round($d.Size / 1GB, 2)
        $healthClass = if ($d.HealthStatus -eq "Healthy") { "ok" } else { "bad" }
        $dName  = ConvertTo-HtmlEscaped $d.FriendlyName
        $dMedia = ConvertTo-HtmlEscaped $d.MediaType
        $dHealth = ConvertTo-HtmlEscaped $d.HealthStatus
        $diskRows += "<tr><td>$($d.DeviceId)</td><td>$dName</td><td>$dMedia</td><td>$sizeGB GB</td><td><span class='badge $healthClass'>$dHealth</span></td></tr>"
    }
} else {
    $diskRows = "<tr><td colspan='5'>No se detectaron discos fisicos mediante WMI/CIM.</td></tr>"
}

# ----------------------------------------------------
# 6. VOLUMENES LOGICOS (ESPACIO EN DISCO)
# ----------------------------------------------------
Write-Host "[6/12] Analizando Espacio en Disco (volumenes logicos)..." -ForegroundColor Yellow
$volumeRows = ""
try {
    $logicalDisks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop
    if ($logicalDisks) {
        foreach ($vol in $logicalDisks) {
            $sizeGB = if ($vol.Size) { [math]::Round($vol.Size / 1GB, 2) } else { 0 }
            $freeGB = if ($vol.FreeSpace) { [math]::Round($vol.FreeSpace / 1GB, 2) } else { 0 }
            $usedGB = [math]::Round($sizeGB - $freeGB, 2)
            $pctFree = if ($sizeGB -gt 0) { [math]::Round(($freeGB / $sizeGB)*100,1) } else { 0 }
            $badge = if ($pctFree -lt 10) { "bad" } elseif ($pctFree -lt 20) { "warn" } else { "ok" }
            $label = ConvertTo-HtmlEscaped $vol.VolumeName
            if (-not $label) { $label = "(sin etiqueta)" }
            $fs = ConvertTo-HtmlEscaped $vol.FileSystem
            $volumeRows += "<tr><td><strong>$($vol.DeviceID)</strong></td><td>$label</td><td>$fs</td><td>$sizeGB GB</td><td>$freeGB GB</td><td>$usedGB GB</td><td><span class='badge $badge'>$pctFree % libre</span></td></tr>"
        }
    } else {
        $volumeRows = "<tr><td colspan='7'>No se detectaron volumenes logicos.</td></tr>"
    }
} catch {
    $volumeRows = "<tr><td colspan='7' class='text-muted'>No se pudo consultar volumenes logicos: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
if (-not $volumeRows) { $volumeRows = "<tr><td colspan='7'>Sin datos de volumenes.</td></tr>" }

# ----------------------------------------------------
# 7. GPU
# ----------------------------------------------------
Write-Host "[7/12] Analizando GPU..." -ForegroundColor Yellow
$gpuRows = ""
try {
    $gpus = Get-CimInstance Win32_VideoController -ErrorAction Stop
    if ($gpus) {
        foreach ($g in $gpus) {
            $gName = ConvertTo-HtmlEscaped $g.Name
            $gChip = ConvertTo-HtmlEscaped $g.VideoProcessor
            $gDriver = ConvertTo-HtmlEscaped $g.DriverVersion
            $gStatus = ConvertTo-HtmlEscaped $g.Status
            $vram = if ($g.AdapterRAM -and $g.AdapterRAM -gt 0) { "$([math]::Round($g.AdapterRAM/1MB,0)) MB" } else { "N/D" }
            $res = if ($g.CurrentHorizontalResolution) { "$($g.CurrentHorizontalResolution)x$($g.CurrentVerticalResolution) @ $($g.CurrentRefreshRate) Hz" } else { "N/D" }
            $gpuRows += "<tr><td>$gName</td><td>$gChip</td><td>$vram</td><td>$gDriver</td><td>$res</td><td>$gStatus</td></tr>"
        }
    } else {
        $gpuRows = "<tr><td colspan='6'>No se detecto GPU via WMI.</td></tr>"
    }
} catch {
    $gpuRows = "<tr><td colspan='6' class='text-muted'>No se pudo consultar GPU: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}

# ----------------------------------------------------
# 8. RED
# ----------------------------------------------------
Write-Host "[8/12] Analizando Red..." -ForegroundColor Yellow
$netAdapterRows = ""
$netIpRows = ""
$netPingHtml = ""
try {
    $adapters = @()
    if (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) {
        $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }
    }
    if (-not $adapters -or $adapters.Count -eq 0) {
        $wmiAdapters = Get-CimInstance Win32_NetworkAdapter -ErrorAction SilentlyContinue | Where-Object { $_.NetEnabled -eq $true }
        foreach ($wa in $wmiAdapters) {
            $adapters += [PSCustomObject]@{ Name=$wa.NetConnectionID; InterfaceDescription=$wa.Description; LinkSpeed="N/D"; Status="Up"; MacAddress=$wa.MACAddress }
        }
    }
    if ($adapters) {
        foreach ($na in $adapters) {
            $nName = ConvertTo-HtmlEscaped $na.Name
            $nDesc = ConvertTo-HtmlEscaped $na.InterfaceDescription
            $nSpeed = ConvertTo-HtmlEscaped "$($na.LinkSpeed)"
            $nStatus = ConvertTo-HtmlEscaped $na.Status
            $nMac = ConvertTo-HtmlEscaped $na.MacAddress
            $netAdapterRows += "<tr><td>$nName</td><td>$nDesc</td><td>$nSpeed</td><td><span class='badge ok'>$nStatus</span></td><td>$nMac</td></tr>"
        }
    } else {
        $netAdapterRows = "<tr><td colspan='5' class='text-muted'>No se detectaron adaptadores activos.</td></tr>"
    }
} catch {
    $netAdapterRows = "<tr><td colspan='5' class='text-muted'>Error consultando adaptadores: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
try {
    $ips = @()
    if (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue) {
        $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.IPAddress -notlike "169.254.*" }
    } else {
        $cfg = Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPEnabled -eq $true }
        foreach ($c in $cfg) {
            foreach ($ip in $c.IPAddress) {
                if ($ip -match "^\d+\.\d+\.\d+\.\d+") { $ips += [PSCustomObject]@{ InterfaceAlias=$c.Description; IPAddress=$ip; PrefixLength="N/D" } }
            }
        }
    }
    if ($ips) {
        foreach ($ip in $ips) {
            $ia = ConvertTo-HtmlEscaped $ip.InterfaceAlias
            $addr = ConvertTo-HtmlEscaped $ip.IPAddress
            $pref = $ip.PrefixLength
            $netIpRows += "<tr><td>$ia</td><td>$addr</td><td>$pref</td></tr>"
        }
    } else {
        $netIpRows = "<tr><td colspan='3' class='text-muted'>No se detectaron IPs validas (solo loopback/APIPA).</td></tr>"
    }
} catch {
    $netIpRows = "<tr><td colspan='3' class='text-muted'>Error consultando IPs: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
$pingTargets = @("1.1.1.1","8.8.8.8")
$pingResults = @()
foreach ($t in $pingTargets) {
    $ok = $false
    try { $ok = Test-Connection -ComputerName $t -Count 1 -Quiet -ErrorAction SilentlyContinue } catch { $ok = $false }
    $cls = if ($ok) { "ok" } else { "bad" }
    $txt = if ($ok) { "OK" } else { "Sin respuesta" }
    $pingResults += "<span class='badge $cls'>$t : $txt</span>"
}
$netPingHtml = ($pingResults -join " ")

# ----------------------------------------------------
# 9. VISOR DE EVENTOS (ERRORES 48H)
# ----------------------------------------------------
Write-Host "[9/12] Consultando Visor de Eventos..." -ForegroundColor Yellow
$sinceDate = (Get-Date).AddDays(-$Days)
$eventLogAccessDenied = $false
$events = $null
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'System', 'Application'
        Level     = 1, 2
        StartTime = $sinceDate
    } -ErrorAction Stop
} catch [System.UnauthorizedAccessException] {
    $eventLogAccessDenied = $true
} catch {
    $events = $null
}

$eventRows = ""
$eventCount = 0
$wheaRows = ""
if ($eventLogAccessDenied) {
    $eventRows = "<tr><td colspan='5' class='text-muted'>No se pudo leer el Visor de Eventos (permisos insuficientes). Ejecuta como Administrador para confirmar.</td></tr>"
    $wheaRows = "<tr><td colspan='4' class='text-muted'>No verificado por falta de permisos.</td></tr>"
} elseif ($events) {
    $eventCount = $events.Count
    $topEvents = $events | Select-Object -First 8
    foreach ($e in $topEvents) {
        $msg = $e.Message
        if ($null -ne $msg -and $msg.Length -gt 120) { $msg = $msg.Substring(0, 117) + "..." }
        $msg = ConvertTo-HtmlEscaped $msg
        $prov = ConvertTo-HtmlEscaped $e.ProviderName
        $logN = ConvertTo-HtmlEscaped $e.LogName
        $eventRows += "<tr><td>$($e.TimeCreated.ToString('MM-dd HH:mm'))</td><td>$logN</td><td>$prov</td><td>$($e.Id)</td><td>$msg</td></tr>"
    }
    $wheaEvents = $events | Where-Object { $_.ProviderName -like "*WHEA*" -or $_.Message -like "*memory*" -or $_.Message -like "*memoria*" -or $_.Id -eq 1001 }
    if ($wheaEvents) {
        foreach ($we in ($wheaEvents | Select-Object -First 5)) {
            $wmsg = $we.Message
            if ($null -ne $wmsg -and $wmsg.Length -gt 120) { $wmsg = $wmsg.Substring(0, 117) + "..." }
            $wmsg = ConvertTo-HtmlEscaped $wmsg
            $wprov = ConvertTo-HtmlEscaped $we.ProviderName
            $wheaRows += "<tr class='row-bad'><td>$($we.TimeCreated.ToString('MM-dd HH:mm'))</td><td>$wprov</td><td>$($we.Id)</td><td>$wmsg</td></tr>"
        }
    } else {
        $wheaRows = "<tr><td colspan='4' class='text-ok'>Sin eventos de hardware/memoria (WHEA) en las ultimas 48 horas.</td></tr>"
    }
} else {
    $eventRows = "<tr><td colspan='5' class='text-ok'>No se encontraron errores criticos en las ultimas 48 horas.</td></tr>"
    $wheaRows = "<tr><td colspan='4' class='text-ok'>Sin eventos de hardware/memoria (WHEA) en las ultimas 48 horas.</td></tr>"
}

# ----------------------------------------------------
# 10. DEFENDER / ANTIVIRUS
# ----------------------------------------------------
Write-Host "[10/12] Verificando Defender/Antivirus..." -ForegroundColor Yellow
$defenderHtml = ""
try {
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $rtBadge = if ($mp.RealTimeProtectionEnabled) { "ok" } else { "bad" }
        $avBadge = if ($mp.AntivirusEnabled) { "ok" } else { "bad" }
        $sigAge = ""
        try { $sigAge = $mp.AntivirusSignatureLastUpdated.ToString("yyyy-MM-dd HH:mm") } catch { $sigAge = "N/D" }
        $sigAgeEsc = ConvertTo-HtmlEscaped $sigAge
        $defenderHtml = @"
        <div class="metrics-grid">
            <div class="metric-box"><span class="metric-label">Antivirus Habilitado</span><span class="badge $avBadge">$(if($mp.AntivirusEnabled){"SI"}else{"NO"})</span></div>
            <div class="metric-box"><span class="metric-label">Proteccion Tiempo Real</span><span class="badge $rtBadge">$(if($mp.RealTimeProtectionEnabled){"SI"}else{"NO"})</span></div>
            <div class="metric-box"><span class="metric-label">Firma Actualizada</span><span class="metric-value">$sigAgeEsc</span></div>
            <div class="metric-box"><span class="metric-label">Version Motor</span><span class="metric-value">$(ConvertTo-HtmlEscaped $mp.AMServiceVersion)</span></div>
        </div>
"@
    } else {
        $avProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop
        if ($avProducts) {
            $rows = ""
            foreach ($av in $avProducts) {
                $avName = ConvertTo-HtmlEscaped $av.displayName
                $state = $av.productState
                $stBadge = if ($state -like "*266240*" -or $state -eq 397312) { "ok" } else { "warn" }
                $rows += "<tr><td>$avName</td><td><span class='badge $stBadge'>$state</span></td></tr>"
            }
            $defenderHtml = "<table><thead><tr><th>Producto</th><th>Estado (productState)</th></tr></thead><tbody>$rows</tbody></table>"
        } else {
            $defenderHtml = "<p class='text-muted'>No se detecto informacion de antivirus (Get-MpComputerStatus no disponible y SecurityCenter2 vacio).</p>"
        }
    }
} catch {
    $defenderHtml = "<p class='text-muted'>No se pudo consultar Defender/AV: $(ConvertTo-HtmlEscaped $_.Exception.Message)</p>"
}

# ----------------------------------------------------
# 11. WINDOWS UPDATE
# ----------------------------------------------------
Write-Host "[11/12] Verificando Windows Update..." -ForegroundColor Yellow
$wuHtml = ""
try {
    $sess = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
    $searcher = $sess.CreateUpdateSearcher()
    $result = $searcher.Search("IsInstalled=0 and IsHidden=0")
    $wuCount = $result.Updates.Count
    if ($wuCount -gt 0) {
        $wuBadge = if ($wuCount -gt 10) { "bad" } elseif ($wuCount -gt 0) { "warn" } else { "ok" }
        $wuRows = ""
        $limit = [math]::Min(10, $wuCount)
        for ($i=0; $i -lt $limit; $i++) {
            $u = $result.Updates.Item($i)
            $title = ConvertTo-HtmlEscaped $u.Title
            $kb = ""
            if ($u.KBArticleIDs -and $u.KBArticleIDs.Count -gt 0) { $kb = "KB$($u.KBArticleIDs[0])" }
            $wuRows += "<tr><td>$title</td><td>$kb</td></tr>"
        }
        $wuHtml = "<p>Actualizaciones pendientes: <span class='badge $wuBadge'>$wuCount</span></p><table><thead><tr><th>Titulo</th><th>KB</th></tr></thead><tbody>$wuRows</tbody></table>"
        if ($wuCount -gt 10) { $wuHtml += "<p class='text-muted' style='margin-top:8px;'>Mostrando 10 de $wuCount.</p>" }
    } else {
        $wuHtml = "<p class='text-ok'>No hay actualizaciones pendientes detectadas.</p>"
    }
} catch {
    $wuHtml = "<p class='text-muted'>No se pudo consultar Windows Update (requiere permisos o servicio deshabilitado): $(ConvertTo-HtmlEscaped $_.Exception.Message)</p>"
}

# ----------------------------------------------------
# 12. PROGRAMAS DESACTUALIZADOS (WINGET)
# ----------------------------------------------------
Write-Host "[12/12] Comprobando Software Desactualizado..." -ForegroundColor Yellow
$wingetRows = ""
if (Get-Command winget -ErrorAction SilentlyContinue) {
    $wingetOut = Invoke-WingetSafe -TimeoutSec 25
    $lines = $wingetOut -split "`r`n" | Where-Object { $_ -match '\S+' -and $_ -notmatch 'Name|Nombre|---|Winget' }
    if ($lines) {
        foreach ($line in ($lines | Select-Object -First 10)) {
            $wingetRows += "<tr><td>$(ConvertTo-HtmlEscaped $line)</td></tr>"
        }
    } else {
        $wingetRows = "<tr><td class='text-ok'>Todos los paquetes analizados por Winget estan actualizados.</td></tr>"
    }
} else {
    $wingetRows = "<tr><td class='text-muted'>Winget no esta disponible en este sistema. Se recomienda revisar manualmente.</td></tr>"
}

# ----------------------------------------------------
# GENERACION DE HTML
# ----------------------------------------------------
$cpuBadgeClass = if ($cpuLoad -gt 85) { "bad" } elseif ($cpuLoad -gt 60) { "warn" } else { "ok" }
$ramBadgeClass = if ($ramPct -gt 90) { "bad" } elseif ($ramPct -gt 75) { "warn" } else { "ok" }
$driverBadgeClass = if ($badDrivers) { "bad" } else { "ok" }

$osNameEsc     = ConvertTo-HtmlEscaped $osName
$cpuNameEsc    = ConvertTo-HtmlEscaped $cpuName
$computerEsc   = ConvertTo-HtmlEscaped $ComputerName

$htmlContent = @"
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Diagnostico - $computerEsc</title>
    <style>
        :root {
            --bg: #0f172a;
            --card-bg: #1e293b;
            --card-border: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-blue: #38bdf8;
            --ok-color: #22c55e;
            --warn-color: #eab308;
            --bad-color: #ef4444;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        body { background-color: var(--bg); color: var(--text-main); padding: 24px; line-height: 1.5; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--card-border); padding-bottom: 16px; margin-bottom: 24px; }
        .header h1 { font-size: 24px; color: var(--accent-blue); }
        .header p { color: var(--text-muted); font-size: 14px; }
        .grid-summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .summary-card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 8px; padding: 16px; }
        .summary-card span.label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; display: block; margin-bottom: 4px; }
        .summary-card div.val { font-size: 18px; font-weight: bold; color: var(--text-main); }
        .card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 8px; padding: 20px; margin-bottom: 24px; }
        .card h3 { color: var(--accent-blue); margin-bottom: 14px; font-size: 18px; border-bottom: 1px solid var(--card-border); padding-bottom: 8px; }
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }
        .metric-box { background: rgba(15, 23, 42, 0.5); padding: 12px; border-radius: 6px; border: 1px solid var(--card-border); }
        .metric-label { font-size: 12px; color: var(--text-muted); display: block; }
        .metric-value { font-size: 16px; font-weight: bold; margin-top: 4px; display: block; }
        table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 14px; }
        th { text-align: left; background: rgba(15, 23, 42, 0.8); color: var(--text-muted); padding: 10px; border-bottom: 1px solid var(--card-border); }
        td { padding: 10px; border-bottom: 1px solid var(--card-border); }
        tr:hover { background: rgba(255, 255, 255, 0.02); }
        tr.row-bad { background: rgba(239, 68, 68, 0.1); }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; }
        .badge.ok { background: rgba(34, 197, 94, 0.2); color: var(--ok-color); border: 1px solid var(--ok-color); }
        .badge.warn { background: rgba(234, 179, 8, 0.2); color: var(--warn-color); border: 1px solid var(--warn-color); }
        .badge.bad { background: rgba(239, 68, 68, 0.2); color: var(--bad-color); border: 1px solid var(--bad-color); }
        .text-ok { color: var(--ok-color); }
        .text-muted { color: var(--text-muted); }
        .footer { text-align: center; color: var(--text-muted); font-size: 12px; margin-top: 30px; }
    </style>
</head>
<body>

    <div class="header">
        <div>
            <h1>Reporte de Diagnostico de Sistema</h1>
            <p>Equipo: <strong>$computerEsc</strong> | Generado el $ReportDate</p>
        </div>
        <div>
            <span class="badge ok">Estado General Recopilado</span>
        </div>
    </div>

    <!-- OneDrive warning -->
    $(if($oneDriveWarn){"<div class=card style=border-color: var(--warn-color);><h3 style=color:var(--warn-color);>Aviso: Escritorio en OneDrive</h3><p class=text-muted>El reporte contiene datos personales (hostname, MAC, admins) y se guardara en OneDrive sincronizado a la nube. LOPDP: verifica retencion y manejo.</p></div>"})

    <!-- RESUMEN GENERAL -->
    <div class="grid-summary">
        <div class="summary-card">
            <span class="label">Sistema Operativo</span>
            <div class="val">$osNameEsc</div>
            <p style="font-size:12px; color:var(--text-muted);">Ver: $osVersion | Uptime: $uptimeStr</p>
        </div>
        <div class="summary-card">
            <span class="label">Uso de CPU</span>
            <div class="val">$cpuLoad %</div>
            <span class="badge $cpuBadgeClass" style="margin-top:6px;">$cpuNameEsc</span>
        </div>
        <div class="summary-card">
            <span class="label">Memoria RAM</span>
            <div class="val">$usedRamGB GB / $totalRamGB GB</div>
            <span class="badge $ramBadgeClass" style="margin-top:6px;">Uso: $ramPct %</span>
            <p style="font-size:11px; color:var(--text-muted); margin-top:6px;">Disponible real (descontando cache): $ramAvailableGB GB</p>
        </div>
        <div class="summary-card">
            <span class="label">Dispositivos / Drivers</span>
            <div class="val">$(if ($badDrivers) { "$($badDrivers.Count) con fallos" } else { "100% Correctos" })</div>
            <span class="badge $driverBadgeClass" style="margin-top:6px;">$(if ($badDrivers) { "Atencion Requerida" } else { "Sin Errores" })</span>
        </div>
    </div>

    <!-- BATERIA -->
    $batteryHtml

    <!-- ALMACENAMIENTO FISICO -->
    <div class="card">
        <h3>Almacenamiento y Discos Fisicos (S.M.A.R.T.)</h3>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Modelo / Dispositivo</th>
                    <th>Tipo</th>
                    <th>Capacidad</th>
                    <th>Estado S.M.A.R.T.</th>
                </tr>
            </thead>
            <tbody>
                $diskRows
            </tbody>
        </table>
    </div>

    <!-- VOLUMENES LOGICOS -->
    <div class="card">
        <h3>Volumenes Logicos (espacio en disco)</h3>
        <table>
            <thead>
                <tr>
                    <th>Unidad</th>
                    <th>Etiqueta</th>
                    <th>FS</th>
                    <th>Capacidad</th>
                    <th>Libre</th>
                    <th>Usado</th>
                    <th>Estado</th>
                </tr>
            </thead>
            <tbody>
                $volumeRows
            </tbody>
        </table>
        <p class="text-muted" style="font-size:12px; margin-top:8px;">Alerta si &lt;10% libre (bad) o &lt;20% libre (warn). Disco lleno es causa comun de lentitud y fallos de update.</p>
    </div>

    <!-- GPU -->
    <div class="card">
        <h3>GPU / Video</h3>
        <table>
            <thead>
                <tr>
                    <th>Modelo</th>
                    <th>Procesador</th>
                    <th>VRAM</th>
                    <th>Driver</th>
                    <th>Resolucion</th>
                    <th>Estado</th>
                </tr>
            </thead>
            <tbody>
                $gpuRows
            </tbody>
        </table>
    </div>

    <!-- RED -->
    <div class="card">
        <h3>Red</h3>
        <h4 style="color:var(--text-muted); font-size:14px; margin:10px 0 6px 0;">Adaptadores activos</h4>
        <table>
            <thead>
                <tr>
                    <th>Nombre</th>
                    <th>Descripcion</th>
                    <th>Velocidad</th>
                    <th>Estado</th>
                    <th>MAC</th>
                </tr>
            </thead>
            <tbody>
                $netAdapterRows
            </tbody>
        </table>
        <h4 style="color:var(--text-muted); font-size:14px; margin:14px 0 6px 0;">Direcciones IPv4</h4>
        <table>
            <thead>
                <tr>
                    <th>Interfaz</th>
                    <th>IP</th>
                    <th>Prefijo</th>
                </tr>
            </thead>
            <tbody>
                $netIpRows
            </tbody>
        </table>
        <p style="margin-top:12px;">Conectividad: $netPingHtml <span class="text-muted" style="font-size:12px;">(Test-Connection 1.1.1.1 / 8.8.8.8 - 1 intento)</span></p>
    </div>

    <!-- MEMORIA RAM -->
    <div class="card">
        <h3>Modulos de Memoria RAM Instalados</h3>
        <table>
            <thead>
                <tr>
                    <th>Ubicacion / Ranura</th>
                    <th>Capacidad</th>
                    <th>Velocidad</th>
                    <th>Fabricante</th>
                </tr>
            </thead>
            <tbody>
                $ramTableRows
            </tbody>
        </table>
    </div>

    <!-- CONTROLADORES CON ERROR -->
    <div class="card">
        <h3>Controladores y Dispositivos con Estado Anormal</h3>
        <table>
            <thead>
                <tr>
                    <th>Nombre de Dispositivo</th>
                    <th>Clase</th>
                    <th>Codigo de Estado</th>
                </tr>
            </thead>
            <tbody>
                $driversRows
            </tbody>
        </table>
    </div>

    <!-- VISOR DE EVENTOS -->
    <div class="card">
        <h3>Eventos Criticos y Errores (Ultimas 48 Horas) - Total: $eventCount</h3>
        <table>
            <thead>
                <tr>
                    <th>Fecha / Hora</th>
                    <th>Registro</th>
                    <th>Proveedor</th>
                    <th>ID Evento</th>
                    <th>Detalle</th>
                </tr>
            </thead>
            <tbody>
                $eventRows
            </tbody>
        </table>
    </div>

    <!-- ALERTAS DE HARDWARE / MEMORIA (WHEA) -->
    <div class="card">
        <h3>Alertas de Hardware y Memoria (WHEA)</h3>
        <table>
            <thead>
                <tr>
                    <th>Fecha / Hora</th>
                    <th>Proveedor</th>
                    <th>ID Evento</th>
                    <th>Detalle</th>
                </tr>
            </thead>
            <tbody>
                $wheaRows
            </tbody>
        </table>
    </div>

    <!-- DEFENDER / ANTIVIRUS -->
    <div class="card">
        <h3>Defender / Antivirus</h3>
        $defenderHtml
    </div>

    <!-- WINDOWS UPDATE -->
    <div class="card">
        <h3>Windows Update - Actualizaciones Pendientes</h3>
        $wuHtml
    </div>

    <!-- SOFTWARE DESACTUALIZADO -->
    <div class="card">
        <h3>Actualizaciones de Software (Via Winget)</h3>
        <table>
            <thead>
                <tr>
                    <th>Paquete / Estado de Actualizacion</th>
                </tr>
            </thead>
            <tbody>
                $wingetRows
            </tbody>
        </table>
    </div>

    <!-- REINICIO PENDIENTE -->
    <div class="card">
        <h3>Reinicio pendiente</h3>
        <table><tbody>
                $pendingRebootRows
            </tbody></table>
        <p class="text-muted" style="font-size:12px; margin-top:8px;">Si hay reinicio pendiente, el equipo puede estar lento y updates no aplicados. Reiniciar antes de re-auditar.</p>
    </div>

    <div class="footer">
        Reporte generado automaticamente mediante Script de PowerShell | Soporte Tecnico e Infraestructura
    </div>

</body>
</html>
"@

# Guardar con UTF-8 garantizado (valido PS 5.1 y PS 7+).
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
Write-Host " Reporte generado con exito en:" -ForegroundColor Green
Write-Host " $OutputFile" -ForegroundColor Cyan
if ($oneDriveWarn) { Write-Host " ADVERTENCIA: Destino en OneDrive - datos personales en nube" -ForegroundColor Yellow }
try {
    $hash = (Get-FileHash -Path $OutputFile -Algorithm SHA256 -ErrorAction Stop).Hash
    Write-Host " SHA256: $hash" -ForegroundColor Gray
    $hashHtml = "<p class='text-muted' style='font-size:11px; margin-top:8px;'>SHA256: $hash | UTC: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'))Z | Host: $computerEsc</p>"
    # Append hash to HTML file as comment for integrity
    Add-Content -Path $OutputFile -Value "<!-- SHA256:$hash UTC:$((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'))Z -->" -ErrorAction SilentlyContinue
} catch {}
Write-Host "==================================================" -ForegroundColor Green

if (-not $NoOpen) { Start-Process $OutputFile } else { Write-Host " NoOpen: reporte no abierto automaticamente." -ForegroundColor Gray }
# Exit code para RMM: 0=ok, 1=hallazgos
$exitBad = 0
try { if ($pendingRebootRows -like "*bad*") { $exitBad++ } } catch {}
if ($totalBad -gt 0 -or $exitBad -gt 0) { exit 1 } else { exit 0 }
"""
dst.write_text(content, encoding="utf-8")
print("Wrote", len(content.splitlines()), "lines")
