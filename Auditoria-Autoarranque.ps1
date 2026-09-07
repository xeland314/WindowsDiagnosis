<#
.SYNOPSIS
    Auditoria de programas de autoarranque - deteccion de Masquerading (T1036) y
    Resource Hijacking (T1496) en Windows, con reporte HTML.
.DESCRIPTION
    Enumera TODAS las fuentes de autoarranque en Windows (Registro Run/RunOnce en
    HKLM y HKCU, carpeta de Inicio, Tareas Programadas y Servicios en auto-inicio),
    resuelve cada ejecutable a su firma digital y metadatos de fabricante (CompanyName/
    ProductName), y senala cuando el binario vive en la carpeta de un programa cuyo
    fabricante NO coincide con quien firmo/compilo el ejecutable.

    Este es exactamente el patron del caso FAHConsole.exe: un binario legitimo, firmado,
    0/70 en VirusTotal, pero implantado dentro de C:\Program Files\WinZip\ sin relacion
    con WinZip. Un antivirus nunca lo va a marcar porque no es malicioso "en si mismo" -
    la anomalia es de UBICACION, no de firma.

    Tambien reporta throttling de CPU, procesos top y 6 vectores ciegos adicionales:
    WMI subscriptions (T1546.003), exclusiones de Defender, conexiones de red a procesos,
    extensiones de navegador, estado StartupApproved y IFEO/AppInit_DLLs.

    Disenado para funcionar sin instalacion y ser compatible con PowerShell 5.1 y 7+.
.NOTES
    Sin dependencias externas. Requiere PowerShell 5.1+.
    La mayoria de secciones no requiere Administrador; WMI subscriptions, Defender
    exclusiones y StartupApproved de HKLM si pueden requerirlo.
    Si Windows bloquea el script por venir de otra PC/USB: Unblock-File -Path .\Auditoria-Autoarranque.ps1
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

function ConvertTo-HtmlEscaped {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

$ReportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ComputerName = $env:COMPUTERNAME
$desktopInfo = Get-DesktopPathSafe
$desktopPath = $desktopInfo.Path
$oneDriveWarn = $desktopInfo.IsOneDrive
if ($OutputPath) { $OutputFile = $OutputPath } else { $OutputFile = Join-Path $desktopPath ("Auditoria_Autoarranque_${ComputerName}_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".html") }

$KnownIOCHashes = @{
    "CD0AE8B96FB2200E63DAE28B45964B4D56BDAF999B79ED23BAE79F9C5C9CD5B5" = "FAHConsole.exe implantado en WinZip (caso ISABEL-3501)"
    "43E0E6802939964B526244B2CFF653F27964738BD1AE8E6513361E48E903380C" = "CloseFAH.exe implantado en WinZip (caso ISABEL-3501)"
    "9DFD0449FF947084DC5FC0B1B1047BA0DD561867AA628AE605118624593DB3C3" = "DIPUS.xml implantado en WinZip (caso ISABEL-3501)"
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " Auditoria de Autoarranque - $ComputerName" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# ----------------------------------------------------
# FUNCIONES AUXILIARES
# ----------------------------------------------------

function Get-ExecutablePathFromCommand {
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    if ($Command -match '"([^"]+?\.exe)"') { return $matches[1] }
    if ($Command -match '([A-Za-z]:\\[^"]+?\.exe)') { return $matches[1] }
    return $Command.Trim('"').Trim()
}

function Get-NormalizedTokens {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $clean = ($Text -replace '[^a-zA-Z0-9]', ' ').ToLower()
    return ($clean -split '\s+') | Where-Object { $_.Length -gt 2 }
}

function Test-VendorFolderMismatch {
    param([string]$Path, [string]$Company, [string]$Product)
    if (-not (Test-Path $Path)) { return $null }
    $segments = $Path -split '\\'
    $idx = -1
    for ($i = 0; $i -lt $segments.Count; $i++) {
        if ($segments[$i] -match '^Program Files( \(x86\))?$' -or $segments[$i] -eq 'ProgramData') {
            $idx = $i; break
        }
    }
    if ($idx -lt 0 -or ($idx + 1) -ge $segments.Count) { return $null }
    $folderVendor = $segments[$idx + 1]
    if ([string]::IsNullOrWhiteSpace($Company) -and [string]::IsNullOrWhiteSpace($Product)) {
        return @{ Mismatch = $false; ExpectedFolder = $folderVendor; Reason = "Sin metadatos de fabricante (no verificable)" }
    }
    $folderTokens = Get-NormalizedTokens $folderVendor
    $metaTokens = @()
    if ($Company) { $metaTokens += Get-NormalizedTokens $Company }
    if ($Product) { $metaTokens += Get-NormalizedTokens $Product }
    $overlap = $folderTokens | Where-Object { $metaTokens -contains $_ }
    if ($overlap.Count -eq 0) {
        return @{ Mismatch = $true; ExpectedFolder = $folderVendor; Reason = "'$Company / $Product' no coincide con la carpeta '$folderVendor'" }
    }
    return @{ Mismatch = $false; ExpectedFolder = $folderVendor; Reason = "Coincide" }
}

function Get-FileAudit {
    param([string]$Path)
    $result = [PSCustomObject]@{
        Path        = $Path
        Exists      = $false
        Company     = ""
        Product     = ""
        SignStatus  = "N/A"
        Signer      = ""
        Hash        = ""
        IOCMatch    = $null
        Mismatch    = $null
    }
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path $Path -PathType Leaf)) {
        return $result
    }
    $result.Exists = $true
    try {
        $vi = (Get-Item $Path).VersionInfo
        $result.Company = $vi.CompanyName
        $result.Product = $vi.ProductName
    } catch {}
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        $result.SignStatus = $sig.Status.ToString()
        if ($sig.SignerCertificate) { $result.Signer = $sig.SignerCertificate.Subject }
    } catch {}
    try {
        $result.Hash = (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch {}
    if ($result.Hash -and $KnownIOCHashes.ContainsKey($result.Hash)) {
        $result.IOCMatch = $KnownIOCHashes[$result.Hash]
    }
    $result.Mismatch = Test-VendorFolderMismatch -Path $Path -Company $result.Company -Product $result.Product
    return $result
}

# ----------------------------------------------------
# 1. RECOLECCION DE FUENTES DE AUTOARRANQUE
# ----------------------------------------------------
Write-Host "[1/11] Recolectando fuentes de autoarranque (Run, Inicio, Tareas, Servicios)..." -ForegroundColor Yellow
$entries = New-Object System.Collections.Generic.List[Object]
Get-CimInstance Win32_StartupCommand | ForEach-Object {
    $entries.Add([PSCustomObject]@{
        Source  = "Registro/Inicio ($($_.Location))"
        Name    = $_.Name
        RawCmd  = $_.Command
    })
}
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.State -ne 'Disabled' -and (
        $_.Triggers | Where-Object { $_.CimClass.CimClassName -match 'LogonTrigger|BootTrigger' }
    )
} | ForEach-Object {
    foreach ($action in $_.Actions) {
        if ($action.Execute) {
            $cmd = "$($action.Execute) $($action.Arguments)"
            $entries.Add([PSCustomObject]@{
                Source = "Tarea Programada ($($_.TaskPath)$($_.TaskName))"
                Name   = $_.TaskName
                RawCmd = $cmd
            })
        }
    }
}
Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' } | ForEach-Object {
    $entries.Add([PSCustomObject]@{
        Source = "Servicio (auto-inicio)"
        Name   = $_.DisplayName
        RawCmd = $_.PathName
    })
}
Write-Host "  -> $($entries.Count) entradas encontradas." -ForegroundColor Gray

# ----------------------------------------------------
# 2. AUDITORIA DE CADA EJECUTABLE
# ----------------------------------------------------
Write-Host "[2/11] Verificando firma, fabricante y hash..." -ForegroundColor Yellow
$auditResults = New-Object System.Collections.Generic.List[Object]
$seenPaths = @{}
foreach ($entry in $entries) {
    $path = Get-ExecutablePathFromCommand -Command $entry.RawCmd
    if (-not $path) { continue }
    $key = $path.ToLower()
    if ($seenPaths.ContainsKey($key)) { continue }
    $seenPaths[$key] = $true
    $audit = Get-FileAudit -Path $path
    $auditResults.Add([PSCustomObject]@{
        Source     = $entry.Source
        Name       = $entry.Name
        Path       = $path
        Exists     = $audit.Exists
        Company    = $audit.Company
        Product    = $audit.Product
        SignStatus = $audit.SignStatus
        Signer     = $audit.Signer
        Hash       = $audit.Hash
        IOCMatch   = $audit.IOCMatch
        Mismatch   = $audit.Mismatch
    })
}
$iocHits = $auditResults | Where-Object { $_.IOCMatch }
$mismatchHits = $auditResults | Where-Object { $_.Mismatch -and $_.Mismatch.Mismatch }

# ----------------------------------------------------
# 3. THROTTLING DE CPU - metrica fiable (no CurrentClockSpeed)
# ----------------------------------------------------
Write-Host "[3/11] Verificando frecuencia de CPU (throttling)..." -ForegroundColor Yellow
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$maxClock = $cpu.MaxClockSpeed
$curClock = $cpu.CurrentClockSpeed
$clockPct = if ($maxClock -gt 0) { [math]::Round(($curClock / $maxClock) * 100, 1) } else { $null }
# Metrica fiable: % Processor Performance (locale-independiente via WMI perf), evita falsos positivos por power plan "eficiencia"
$perfPct = $null
try {
    $perf = Get-CimInstance -ClassName Win32_PerfFormattedData_Counters_ProcessorInformation -Filter "Name='_Total'" -ErrorAction Stop
    if ($perf -and $null -ne $perf.PercentProcessorPerformance) { $perfPct = [math]::Round($perf.PercentProcessorPerformance,1) }
} catch {}
if ($null -eq $perfPct) {
    try {
        $perf2 = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction Stop
        if ($perf2 -and $null -ne $perf2.PercentProcessorTime) { $perfPct = [math]::Round($perf2.PercentProcessorTime,1) }
    } catch {}
}
# Fallback a LoadPercentage si disponible
$loadPct = ($cpu.LoadPercentage)
# Decidir throttling: usa perfPct si existe, sino clockPct
$throttleMetric = if ($null -ne $perfPct) { $perfPct } else { $clockPct }
$throttleWarning = ($throttleMetric -ne $null -and $throttleMetric -lt 60)
$clockNotePerf = if ($null -ne $perfPct) { " (Perf: $perfPct% via ProcessorInformation)" } else { "" }

# ----------------------------------------------------
# 4. PROCESOS TOP CPU - muestreo delta 1.2s (no segundos acumulados)
# ----------------------------------------------------
Write-Host "[4/11] Foto de procesos con mayor CPU (muestreo delta 1.2s)..." -ForegroundColor Yellow
$procSample1 = @{}
try {
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procSample1[$_.Id] = $_.CPU }
} catch {}
Start-Sleep -Milliseconds 1200
$topProcs = Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $before = $procSample1[$_.Id]
    $delta = if ($null -ne $before -and $null -ne $_.CPU) { [math]::Round($_.CPU - $before,2) } else { 0 }
    # Si no hubo delta (proceso nuevo), usar 0; normalizar a % aprox: delta / interval
    $pctApprox = [math]::Round($delta / 1.2,1) # aprox % de un core
    [PSCustomObject]@{ Name=$_.Name; Id=$_.Id; CPU=$delta; CPU_Pct=$pctApprox; RAM_MB=[math]::Round($_.WorkingSet/1MB,1); Path=$_.Path }
} | Sort-Object CPU -Descending | Select-Object -First 10

# ----------------------------------------------------
# 5. WMI SUBSCRIPTIONS (T1546.003) - Persistencia sin archivo
# ----------------------------------------------------
Write-Host "[5/11] Auditando suscripciones WMI (root/subscription)..." -ForegroundColor Yellow
$wmiFilterRows = ""
$wmiConsumerRows = ""
$wmiBindingRows = ""
$wmiSuspiciousCount = 0
try {
    $filters = Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction Stop
    if ($filters) {
        foreach ($f in $filters) {
            $fName = ConvertTo-HtmlEscaped $f.Name
            $fQuery = ConvertTo-HtmlEscaped $f.Query
            $fNS = ConvertTo-HtmlEscaped $f.EventNamespace
            # Heuristica: filtros genericos sospechosos son normales; pero si Query contiene CommandLineEventConsumer indirectamente lo marcamos via binding
            $wmiFilterRows += "<tr><td>$fName</td><td style='word-break:break-all;'>$fQuery</td><td>$fNS</td></tr>"
        }
    } else {
        $wmiFilterRows = "<tr><td colspan='3' class='text-ok'>Sin __EventFilter registrados (normal en workstation limpia).</td></tr>"
    }
} catch {
    $wmiFilterRows = "<tr><td colspan='3' class='text-muted'>No se pudo consultar __EventFilter (requiere Admin o WMI no disponible): $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
try {
    $consumers = @()
    $consumers += Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
    $consumers += Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue
    # __EventConsumer base no se instancia directo; capturamos los dos tipos mas abusados
    if ($consumers -and $consumers.Count -gt 0) {
        foreach ($c in $consumers) {
            $cName = ConvertTo-HtmlEscaped $c.Name
            $cCmd = ""
            if ($c.PSObject.Properties['CommandLineTemplate']) { $cCmd = ConvertTo-HtmlEscaped $c.CommandLineTemplate }
            elseif ($c.PSObject.Properties['ScriptText']) { $cCmd = ConvertTo-HtmlEscaped $c.ScriptText.Substring(0,[math]::Min(200,$c.ScriptText.Length)) }
            $cType = ConvertTo-HtmlEscaped $c.CimClass.CimClassName
            $wmiConsumerRows += "<tr class='row-bad'><td>$cName</td><td>$cType</td><td style='word-break:break-all;'>$cCmd</td></tr>"
            $wmiSuspiciousCount++
        }
    } else {
        $wmiConsumerRows = "<tr><td colspan='3' class='text-ok'>Sin CommandLine/ActiveScript consumers (limpio).</td></tr>"
    }
} catch {
    $wmiConsumerRows = "<tr><td colspan='3' class='text-muted'>No se pudo consultar consumers: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
try {
    $bindings = Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue
    if ($bindings) {
        foreach ($b in $bindings) {
            $bFilter = ConvertTo-HtmlEscaped $b.Filter
            $bCons = ConvertTo-HtmlEscaped $b.Consumer
            $wmiBindingRows += "<tr><td style='word-break:break-all;'>$bFilter</td><td style='word-break:break-all;'>$bCons</td></tr>"
            # Si hay binding, indica persistencia activa
            if ($wmiSuspiciousCount -eq 0) { $wmiSuspiciousCount = 1 }
        }
    } else {
        $wmiBindingRows = "<tr><td colspan='2' class='text-muted'>Sin bindings (sin persistencia WMI activa).</td></tr>"
    }
} catch {
    $wmiBindingRows = "<tr><td colspan='2' class='text-muted'>No se pudo consultar bindings: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
$wmiBadge = if ($wmiSuspiciousCount -gt 0) { "bad" } else { "ok" }
$wmiBadgeText = if ($wmiSuspiciousCount -gt 0) { "$wmiSuspiciousCount sospechoso(s)" } else { "Limpio" }

# ----------------------------------------------------
# 6. EXCLUSIONES DE DEFENDER
# ----------------------------------------------------
Write-Host "[6/11] Auditando exclusiones de Defender..." -ForegroundColor Yellow
$defenderExclusionHtml = ""
$defenderExclusionRows = ""
$defenderExclusionCount = 0
try {
    if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
        $pref = Get-MpPreference -ErrorAction Stop
        $allEx = @()
        if ($pref.ExclusionPath) { foreach ($p in $pref.ExclusionPath) { $allEx += [PSCustomObject]@{ Tipo="Ruta"; Valor=$p } } }
        if ($pref.ExclusionProcess) { foreach ($p in $pref.ExclusionProcess) { $allEx += [PSCustomObject]@{ Tipo="Proceso"; Valor=$p } } }
        if ($pref.ExclusionExtension) { foreach ($p in $pref.ExclusionExtension) { $allEx += [PSCustomObject]@{ Tipo="Extension"; Valor=$p } } }
        if ($pref.ExclusionIpAddress) { foreach ($p in $pref.ExclusionIpAddress) { $allEx += [PSCustomObject]@{ Tipo="IP"; Valor=$p } } }
        if ($allEx.Count -gt 0) {
            $defenderExclusionCount = $allEx.Count
            foreach ($ex in $allEx) {
                $t = ConvertTo-HtmlEscaped $ex.Tipo
                $v = ConvertTo-HtmlEscaped $ex.Valor
                # Flag si excluye carpetas de programa sensibles sin justificacion
                $isSuspicious = ($v -like "*WinZip*" -or $v -like "*Temp*" -or $v -like "*AppData*" -or $ex.Tipo -eq "Extension" -and $v -eq "exe")
                $cls = if ($isSuspicious) { "row-bad" } else { "" }
                $badge = if ($isSuspicious) { "<span class='badge bad'>Revisar</span>" } else { "<span class='badge ok'>OK</span>" }
                $defenderExclusionRows += "<tr class='$cls'><td>$t</td><td style='word-break:break-all;'>$v</td><td>$badge</td></tr>"
            }
        } else {
            $defenderExclusionRows = "<tr><td colspan='3' class='text-ok'>Sin exclusiones configuradas (recomendado).</td></tr>"
        }
    } else {
        $defenderExclusionRows = "<tr><td colspan='3' class='text-muted'>Get-MpPreference no disponible (Defender no instalado o sin permisos).</td></tr>"
    }
} catch {
    $defenderExclusionRows = "<tr><td colspan='3' class='text-muted'>No se pudo consultar exclusiones: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
$exclusionBadge = if ($defenderExclusionCount -gt 0) { "warn" } else { "ok" }
if ($defenderExclusionRows -match "row-bad") { $exclusionBadge = "bad" }

# ----------------------------------------------------
# 7. CONEXIONES DE RED A PROCESO (mineria activa)
# ----------------------------------------------------
Write-Host "[7/11] Mapeando conexiones de red a procesos..." -ForegroundColor Yellow
$tcpRows = ""
$miningPorts = @(3333,4444,5555,7777,14444,14433,3032,5553,8008,8080)
$miningHits = 0
try {
    $conns = Get-NetTCPConnection -State Established -ErrorAction Stop | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess -First 50
    if ($conns) {
        foreach ($c in $conns) {
            $procName = ""
            try { $procName = (Get-Process -Id $c.OwningProcess -ErrorAction Stop).ProcessName } catch { $procName = "PID $($c.OwningProcess)" }
            $isMiningPort = ($miningPorts -contains $c.RemotePort) -or ($miningPorts -contains $c.LocalPort)
            if ($isMiningPort) { $miningHits++ }
            $cls = if ($isMiningPort) { "row-bad" } else { "" }
            $portBadge = if ($isMiningPort) { "<span class='badge bad'>Puerto minero</span>" } else { "<span class='badge ok'>$($c.RemotePort)</span>" }
            $tcpRows += "<tr class='$cls'><td>$(ConvertTo-HtmlEscaped $procName)</td><td>$($c.OwningProcess)</td><td>$($c.LocalAddress):$($c.LocalPort)</td><td>$($c.RemoteAddress)</td><td>$portBadge</td></tr>"
        }
        if (-not $tcpRows) { $tcpRows = "<tr><td colspan='5' class='text-muted'>Sin conexiones establecidas.</td></tr>" }
    } else {
        $tcpRows = "<tr><td colspan='5' class='text-ok'>Sin conexiones TCP establecidas en este momento.</td></tr>"
    }
} catch {
    # Fallback con netstat si Get-NetTCPConnection no existe (Win7/PS sin modulo NetTCPIP)
    try {
        $ns = netstat -ano 2>&1 | Select-String "ESTABLISHED"
        if ($ns) {
            foreach ($line in ($ns | Select-Object -First 30)) {
                $tcpRows += "<tr><td colspan='5'>$(ConvertTo-HtmlEscaped $line.Line.Trim())</td></tr>"
            }
        } else {
            $tcpRows = "<tr><td colspan='5' class='text-muted'>No se pudo usar Get-NetTCPConnection y netstat no devolvio datos: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
        }
    } catch {
        $tcpRows = "<tr><td colspan='5' class='text-muted'>No se pudo mapear conexiones: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
    }
}
$tcpBadge = if ($miningHits -gt 0) { "bad" } else { "ok" }

# ----------------------------------------------------
# 8. EXTENSIONES DE NAVEGADOR
# ----------------------------------------------------
Write-Host "[8/11] Revisando extensiones de navegador..." -ForegroundColor Yellow
$extRows = ""
$extCount = 0
try {
    $extPaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions\*",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions\*",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Extensions\*"
    )
    $found = @()
    foreach ($pat in $extPaths) {
        $found += Get-ChildItem -Path $pat -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
    }
    # Tambien revisar ExtensionSettings en registro (policy)
    $regExtSettings = @()
    try {
        $regExtSettings += Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionSettings" -ErrorAction SilentlyContinue | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -notmatch "PSPath|PSParent" } | ForEach-Object { $_.Name }
        $regExtSettings += Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionSettings" -ErrorAction SilentlyContinue | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -notmatch "PSPath|PSParent" } | ForEach-Object { $_.Name }
    } catch {}
    if ($found.Count -gt 0) {
        $extCount = $found.Count
        foreach ($fp in ($found | Select-Object -First 40)) {
            $esc = ConvertTo-HtmlEscaped $fp
            # Extraer ID de extension (carpeta padre)
            $id = Split-Path $fp -Leaf
            # Heuristica minima: si la carpeta no tiene manifest legible, marcar warn
            $manifest = Join-Path $fp "manifest.json"
            $hasManifest = Test-Path $manifest
            $badge = if ($hasManifest) { "<span class='badge ok'>OK</span>" } else { "<span class='badge warn'>Sin manifest</span>" }
            $extRows += "<tr><td style='word-break:break-all;'>$esc</td><td>$badge</td></tr>"
        }
        if ($found.Count -gt 40) { $extRows += "<tr><td colspan='2' class='text-muted'>Mostrando 40 de $($found.Count) extensiones. Revisa manualmente las restantes.</td></tr>" }
    } else {
        $extRows = "<tr><td colspan='2' class='text-muted'>No se encontraron carpetas de extensiones (o navegadores no instalados).</td></tr>"
    }
    if ($regExtSettings.Count -gt 0) {
        $extRows += "<tr><td colspan='2'><strong>ExtensionSettings en registro (policy):</strong> $(ConvertTo-HtmlEscaped ($regExtSettings -join ', '))</td></tr>"
    }
} catch {
    $extRows = "<tr><td colspan='2' class='text-muted'>No se pudo revisar extensiones: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
$extBadge = if ($extCount -gt 20) { "warn" } else { "ok" }

# ----------------------------------------------------
# 9. ESTADO StartupApproved (Habilitado/Deshabilitado)
# ----------------------------------------------------
Write-Host "[9/11] Verificando estado StartupApproved..." -ForegroundColor Yellow
$approvedRows = ""
try {
    $approvedPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
    )
    $foundApproved = @()
    foreach ($ap in $approvedPaths) {
        try {
            $props = Get-ItemProperty -Path $ap -ErrorAction Stop
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -match "^PSPath|^PSParent|^PSChild") { continue }
                $raw = $p.Value
                $state = "Desconocido"
                $badge = "warn"
                if ($raw -is [byte[]] -and $raw.Length -gt 0) {
                    # Byte 0: 0x02 = habilitado, 0x03 = deshabilitado (documentado por NirSoft/Autoruns)
                    if ($raw[0] -eq 2) { $state = "Habilitado"; $badge = "ok" }
                    elseif ($raw[0] -eq 3) { $state = "Deshabilitado"; $badge = "warn" }
                    else { $state = "Valor $($raw[0])"; $badge = "warn" }
                } else {
                    $state = "$raw"
                }
                $foundApproved += [PSCustomObject]@{ Path=$ap; Name=$p.Name; State=$state; Badge=$badge }
            }
        } catch {}
    }
    if ($foundApproved.Count -gt 0) {
        foreach ($fa in $foundApproved) {
            $faPath = ConvertTo-HtmlEscaped $fa.Path
            $faName = ConvertTo-HtmlEscaped $fa.Name
            $faState = ConvertTo-HtmlEscaped $fa.State
            $badgeCls = $fa.Badge
            $approvedRows += "<tr><td>$faPath</td><td>$faName</td><td><span class='badge $badgeCls'>$faState</span></td></tr>"
        }
    } else {
        $approvedRows = "<tr><td colspan='3' class='text-muted'>No se encontraron entradas StartupApproved (o sin permisos para HKLM).</td></tr>"
    }
} catch {
    $approvedRows = "<tr><td colspan='3' class='text-muted'>No se pudo consultar StartupApproved: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}

# ----------------------------------------------------
# 10. IFEO / AppInit_DLLs
# ----------------------------------------------------
Write-Host "[10/11] Revisando IFEO y AppInit_DLLs..." -ForegroundColor Yellow
$ifeoRows = ""
$appInitHtml = ""
try {
    $ifeoBase = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    $ifeoItems = Get-ChildItem -Path $ifeoBase -ErrorAction SilentlyContinue
    $ifeoHits = @()
    foreach ($item in $ifeoItems) {
        try {
            $props = Get-ItemProperty -Path $item.PSPath -ErrorAction SilentlyContinue
            if ($props.Debugger -or $props.VerifierDlls -or $props.GlobalFlag) {
                $exe = ConvertTo-HtmlEscaped $item.PSChildName
                $dbg = ConvertTo-HtmlEscaped "$($props.Debugger)"
                $ifeoHits += "<tr class='row-bad'><td>$exe</td><td style='word-break:break-all;'>$dbg</td><td>Debugger/VerifierDlls presente</td></tr>"
            }
        } catch {}
    }
    if ($ifeoHits.Count -gt 0) {
        $ifeoRows = ($ifeoHits -join "")
    } else {
        $ifeoRows = "<tr><td colspan='3' class='text-ok'>Sin secuestros IFEO detectados (sin Debugger).</td></tr>"
    }
} catch {
    $ifeoRows = "<tr><td colspan='3' class='text-muted'>No se pudo consultar IFEO: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
try {
    $appInit = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -ErrorAction Stop
    $dlls = $appInit.AppInit_DLLs
    $enabled = $appInit.LoadAppInit_DLLs
    $dllsEsc = ConvertTo-HtmlEscaped "$dlls"
    $enBadge = if ($enabled -eq 1 -and $dlls) { "bad" } elseif ($dlls) { "warn" } else { "ok" }
    $enText = if ($enabled -eq 1) { "Habilitado (1)" } elseif ($enabled -eq 0) { "Deshabilitado (0)" } else { "N/D ($enabled)" }
    $appInitHtml = "<p>LoadAppInit_DLLs: <span class='badge $enBadge'>$enText</span> | DLLs: <code>$dllsEsc</code></p>"
    if ($enabled -eq 1 -and $dlls) {
        $appInitHtml += "<p class='text-muted' style='font-size:12px; margin-top:4px;'>AppInit_DLLs inyecta DLLs en cada proceso user32.dll - si no lo configuraste tu, es sospechoso.</p>"
    }
} catch {
    $appInitHtml = "<p class='text-muted'>No se pudo consultar AppInit_DLLs: $(ConvertTo-HtmlEscaped $_.Exception.Message)</p>"
}

# ----------------------------------------------------
# 11. PERSISTENCIA AVANZADA - Checklist Autoruns (Wow6432Node, Policies, COM, Winlogon, etc.)
# ----------------------------------------------------
Write-Host "[11/11] Auditando persistencia avanzada (Autoruns checklist)..." -ForegroundColor Yellow
$advWowRows = ""; $advPoliciesRows = ""; $advComRows = ""; $advWinlogonRows = ""; $advExefileRows = ""
$advOfficeRows = ""; $advProfileRows = ""; $advNativeRows = ""; $advHostsRows = ""; $advProxyRows = ""
$advUnquotedRows = ""; $advTasksTempRows = ""; $advRareRows = ""; $advLnkRows = ""
$advBad = 0
# Wow6432Node + HKU Run de otros perfiles
try {
    $wowPaths = @(
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($wp in $wowPaths) {
        try {
            $props = Get-ItemProperty -Path $wp -ErrorAction Stop
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -match "^PS") { continue }
                $val = ConvertTo-HtmlEscaped "$($p.Value)"
                $name = ConvertTo-HtmlEscaped $p.Name
                $isWow = ($wp -like "*Wow6432Node*")
                $badge = if ($isWow) { "warn" } else { "ok" }
                # Heuristica: valor en Temp/AppData es sospechoso
                if ("$($p.Value)" -like "*Temp*" -or "$($p.Value)" -like "*AppData*") { $badge = "bad"; $advBad++ }
                $advWowRows += "<tr class='$(if($badge -eq 'bad'){'row-bad'})'><td>$wp</td><td>$name</td><td style='word-break:break-all;'>$val</td><td><span class='badge $badge'>$(if($isWow){'32-bit'}else{'OK'})</span></td></tr>"
            }
        } catch {}
    }
    # HKU: enumerar SIDs cargados
    try {
        $hku = Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like "S-1-5-21-*" }
        foreach ($sid in $hku) {
            $path = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
            try {
                $props = Get-ItemProperty -Path $path -ErrorAction Stop
                foreach ($p in $props.PSObject.Properties) {
                    if ($p.Name -match "^PS") { continue }
                    $val = ConvertTo-HtmlEscaped "$($p.Value)"
                    $name = ConvertTo-HtmlEscaped $p.Name
                    $sidShort = $sid.PSChildName.Substring($sid.PSChildName.Length-4)
                    $isTemp = ("$($p.Value)" -like "*Temp*")
                    $badge = if ($isTemp) { "bad" } else { "warn" }
                    if ($isTemp) { $advBad++ }
                    $advWowRows += "<tr class='$(if($badge -eq 'bad'){'row-bad'})'><td>HKU\...$sidShort\...\Run</td><td>$name</td><td style='word-break:break-all;'>$val</td><td><span class='badge $badge'>Perfil $sidShort</span></td></tr>"
                }
            } catch {}
        }
    } catch {}
    if (-not $advWowRows) { $advWowRows = "<tr><td colspan='4' class='text-ok'>Sin entradas Wow6432Node/HKU adicionales (normal).</td></tr>" }
} catch {
    $advWowRows = "<tr><td colspan='4' class='text-muted'>No se pudo verificar Wow6432Node/HKU: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
# Policies\Explorer\Run (malware)
try {
    $polPaths = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run","HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")
    foreach ($pp in $polPaths) {
        try {
            $props = Get-ItemProperty -Path $pp -ErrorAction Stop
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -match "^PS") { continue }
                $advPoliciesRows += "<tr class='row-bad'><td>$pp</td><td>$(ConvertTo-HtmlEscaped $p.Name)</td><td style='word-break:break-all;'>$(ConvertTo-HtmlEscaped $p.Value)</td><td><span class='badge bad'>Malware-like</span></td></tr>"
                $advBad++
            }
        } catch {}
    }
    if (-not $advPoliciesRows) { $advPoliciesRows = "<tr><td colspan='4' class='text-ok'>Sin Policies\Explorer\Run (limpio).</td></tr>" }
} catch {
    $advPoliciesRows = "<tr><td colspan='4' class='text-muted'>Error Policies Run: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
# COM hijacking HKCU\Software\Classes\CLSID
try {
    $comBase = "HKCU:\Software\Classes\CLSID"
    $comItems = Get-ChildItem -Path $comBase -ErrorAction SilentlyContinue | Select-Object -First 200
    $comHits = @()
    foreach ($item in $comItems) {
        $inproc = Join-Path $item.PSPath "InprocServer32"
        if (Test-Path $inproc) {
            try {
                $val = (Get-ItemProperty -Path $inproc -ErrorAction Stop)."(default)"
                if ($val -and $val -ne "" -and $val -notlike "*System32*" -and $val -notlike "*Windows*") {
                    # Filtrar valores vacios normales
                    $comHits += "<tr class='row-bad'><td>$(ConvertTo-HtmlEscaped $item.PSChildName)</td><td style='word-break:break-all;'>$(ConvertTo-HtmlEscaped $val)</td><td><span class='badge bad'>Revisar</span></td></tr>"
                    $advBad++
                }
            } catch {}
        }
    }
    if ($comHits.Count -gt 0) { $advComRows = ($comHits | Select-Object -First 20) -join ""; if ($comHits.Count -gt 20) { $advComRows += "<tr><td colspan='3' class='text-muted'>+ $($comHits.Count-20) mas (revisar completo).</td></tr>" } }
    else { $advComRows = "<tr><td colspan='3' class='text-ok'>Sin COM hijacking en HKCU\Classes\CLSID\InprocServer32 (muestra 200).</td></tr>" }
} catch {
    $advComRows = "<tr><td colspan='3' class='text-muted'>No se pudo verificar COM hijacking: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
# Winlogon Userinit/Shell
try {
    $winlogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction Stop
    $userinit = "$($winlogon.Userinit)"
    $shell = "$($winlogon.Shell)"
    $uOk = ($userinit -like "*userinit.exe*")
    $sOk = ($shell -eq "explorer.exe")
    $uBadge = if ($uOk) { "ok" } else { "bad" }
    $sBadge = if ($sOk) { "ok" } else { "bad" }
    if (-not $uOk) { $advBad++ }; if (-not $sOk) { $advBad++ }
    $advWinlogonRows = "<tr><td>Userinit</td><td style='word-break:break-all;'>$(ConvertTo-HtmlEscaped $userinit)</td><td><span class='badge $uBadge'>$(if($uOk){'OK'}else{'Revisar - debe ser userinit.exe,'})</span></td></tr>"
    $advWinlogonRows += "<tr><td>Shell</td><td>$(ConvertTo-HtmlEscaped $shell)</td><td><span class='badge $sBadge'>$(if($sOk){'OK'}else{'Revisar - debe ser explorer.exe'})</span></td></tr>"
} catch {
    $advWinlogonRows = "<tr><td colspan='3' class='text-muted'>No se pudo verificar Winlogon: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
# exefile hijack
try {
    $exefile = $null
    try { $exefile = (Get-ItemProperty -Path "HKCU:\Software\Classes\exefile\shell\open\command" -ErrorAction Stop)."(default)" } catch {}
    if (-not $exefile) { try { $exefile = (Get-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\exefile\shell\open\command" -ErrorAction Stop)."(default)" } catch {} }
    if ($exefile -and $exefile -ne '"%1" %*' -and $exefile -ne '%1 %*') {
        $advExefileRows = "<tr class='row-bad'><td>exefile\shell\open\command</td><td style='word-break:break-all;'>$(ConvertTo-HtmlEscaped $exefile)</td><td><span class='badge bad'>Hijack</span></td></tr>"; $advBad++
    } else {
        $exefileEsc = ConvertTo-HtmlEscaped $(if($exefile){"$exefile"}else{"No personalizado"})
        $advExefileRows = "<tr><td>exefile</td><td>$exefileEsc</td><td><span class='badge ok'>OK</span></td></tr>"
    }
} catch {
    $advExefileRows = "<tr><td colspan='3' class='text-muted'>No se pudo verificar exefile: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
# Office add-ins + XLSTART
try {
    $officeHits = @()
    $officePaths = @("HKCU:\Software\Microsoft\Office\16.0\Word\Addins","HKCU:\Software\Microsoft\Office\16.0\Excel\Addins","HKCU:\Software\Microsoft\Office\16.0\Outlook\Addins","HKCU:\Software\Microsoft\Office\15.0\Word\Addins")
    foreach ($op in $officePaths) {
        try {
            $items = Get-ChildItem -Path $op -ErrorAction Stop
            foreach ($it in $items) {
                $officeHits += "<tr><td>$op\$(ConvertTo-HtmlEscaped $it.PSChildName)</td><td>$(ConvertTo-HtmlEscaped (Get-ItemProperty $it.PSPath -ErrorAction SilentlyContinue | Out-String).Substring(0,200))</td><td><span class='badge warn'>Revisar</span></td></tr>"
            }
        } catch {}
    }
    $xlPaths = @("$env:APPDATA\Microsoft\Excel\XLSTART","$env:APPDATA\Microsoft\Word\STARTUP")
    foreach ($xp in $xlPaths) {
        if (Test-Path $xp) {
            try {
                $files = Get-ChildItem -Path $xp -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match "\.(xlam|dotm|xla)" }
                foreach ($f in $files) {
                    $officeHits += "<tr class='row-bad'><td>$(ConvertTo-HtmlEscaped $xp)</td><td style='word-break:break-all;'>$(ConvertTo-HtmlEscaped $f.FullName)</td><td><span class='badge bad'>Add-in en XLSTART</span></td></tr>"; $advBad++
                }
            } catch {}
        }
    }
    if ($officeHits.Count -gt 0) { $advOfficeRows = ($officeHits -join "") } else { $advOfficeRows = "<tr><td colspan='3' class='text-ok'>Sin Office add-ins sospechosos en XLSTART/Addins.</td></tr>" }
} catch {
    $advOfficeRows = "<tr><td colspan='3' class='text-muted'>Error Office add-ins: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
# PowerShell profiles + history
try {
    $profiles = @($PROFILE.AllUsersAllHosts,$PROFILE.AllUsersCurrentHost,$PROFILE.CurrentUserAllHosts,$PROFILE.CurrentUserCurrentHost)
    $foundProfiles = @()
    foreach ($pr in $profiles) {
        if ($pr -and (Test-Path $pr)) {
            $foundProfiles += "<tr><td style='word-break:break-all;'>$(ConvertTo-HtmlEscaped $pr)</td><td>Existe ($( (Get-Item $pr).Length) bytes)</td><td><span class='badge warn'>Revisar contenido</span></td></tr>"
        }
    }
    $hist = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $hist) {
        $lines = (Get-Content $hist -ErrorAction SilentlyContinue | Select-Object -Last 5) -join "; "
        $foundProfiles += "<tr><td>$(ConvertTo-HtmlEscaped $hist)</td><td style='word-break:break-all;'>$(ConvertTo-HtmlEscaped $lines.Substring(0,[math]::Min(200,$lines.Length)))</td><td><span class='badge ok'>Historial (forense)</span></td></tr>"
    }
    if ($foundProfiles.Count -gt 0) { $advProfileRows = ($foundProfiles -join "") } else { $advProfileRows = "<tr><td colspan='3' class='text-ok'>Sin perfiles de PowerShell personalizados (limpio).</td></tr>" }
} catch {
    $advProfileRows = "<tr><td colspan='3' class='text-muted'>Error profiles: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
# Native messaging hosts + Firefox
try {
    $nativeHits = @()
    $nmPaths = @("HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts","HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts","HKLM:\SOFTWARE\Mozilla\NativeMessagingHosts")
    foreach ($np in $nmPaths) {
        try {
            $items = Get-ChildItem -Path $np -ErrorAction Stop
            foreach ($it in $items) {
                $manifest = (Get-ItemProperty -Path $it.PSPath -ErrorAction SilentlyContinue)."(default)"
                $nativeHits += "<tr><td>$np\$(ConvertTo-HtmlEscaped $it.PSChildName)</td><td style='word-break:break-all;'>$(ConvertTo-HtmlEscaped $manifest)</td><td><span class='badge warn'>Revisar</span></td></tr>"
            }
        } catch {}
    }
    # Firefox extensions
    $firefoxBase = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxBase) {
        try {
            $extFiles = Get-ChildItem -Path $firefoxBase -Recurse -Filter "extensions.json" -ErrorAction SilentlyContinue | Select-Object -First 3
            foreach ($ef in $extFiles) {
                $nativeHits += "<tr><td>Firefox</td><td style='word-break:break-all;'>$(ConvertTo-HtmlEscaped $ef.FullName)</td><td><span class='badge ok'>Perfil Firefox</span></td></tr>"
            }
        } catch {}
    }
    if ($nativeHits.Count -gt 0) { $advNativeRows = ($nativeHits -join "") } else { $advNativeRows = "<tr><td colspan='3' class='text-ok'>Sin Native Messaging Hosts sospechosos.</td></tr>" }
} catch {
    $advNativeRows = "<tr><td colspan='3' class='text-muted'>Error native hosts: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
# hosts + proxy + DNS cache
try {
    $hostsPath = "C:\Windows\System32\drivers\etc\hosts"
    $hostsLines = Get-Content $hostsPath -ErrorAction Stop | Where-Object { $_ -match "^\s*\d+\.\d+\.\d+\.\d+\s+\S+" -and $_ -notmatch "^\s*#" -and $_ -notmatch "localhost" }
    if ($hostsLines) {
        foreach ($hl in ($hostsLines | Select-Object -First 10)) {
            $advHostsRows += "<tr class='row-bad'><td>hosts</td><td style='word-break:break-all;'>$(ConvertTo-HtmlEscaped $hl)</td><td><span class='badge bad'>Entrada no estandar</span></td></tr>"; $advBad++
        }
    } else { $advHostsRows = "<tr><td colspan='3' class='text-ok'>hosts limpio (solo localhost/comentarios).</td></tr>" }
} catch {
    $advHostsRows = "<tr><td colspan='3' class='text-muted'>No se pudo leer hosts: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
try {
    $proxyEnable = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction Stop).ProxyEnable
    $proxyServer = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).ProxyServer
    $autoConfig = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).AutoConfigURL
    $proxyBadge = if ($proxyEnable -eq 1) { "warn" } else { "ok" }
    $advProxyRows = "<tr><td>ProxyEnable</td><td>$proxyEnable</td><td><span class='badge $proxyBadge'>$(if($proxyEnable -eq 1){'Activo'}else{'No'})</span></td></tr>"
    if ($proxyServer) { $advProxyRows += "<tr><td>ProxyServer</td><td style='word-break:break-all;'>$(ConvertTo-HtmlEscaped $proxyServer)</td><td><span class='badge warn'>Revisar</span></td></tr>" }
    if ($autoConfig) { $advProxyRows += "<tr><td>AutoConfigURL</td><td style='word-break:break-all;'>$(ConvertTo-HtmlEscaped $autoConfig)</td><td><span class='badge warn'>PAC</span></td></tr>" }
    try {
        $dns = Get-DnsClientCache -ErrorAction Stop | Select-Object -First 10
        if ($dns) {
            foreach ($d in $dns) {
                $advProxyRows += "<tr><td>DNS Cache</td><td>$(ConvertTo-HtmlEscaped $d.Name) -> $(ConvertTo-HtmlEscaped $d.Data)</td><td class='text-muted'>TTL $($d.TimeToLive)</td></tr>"
            }
        }
    } catch {
        try { $dnsTxt = ipconfig /displaydns 2>&1 | Select-String -Pattern "Nombre de registro" | Select-Object -First 5; foreach ($dd in $dnsTxt) { $advProxyRows += "<tr><td>DNS</td><td>$(ConvertTo-HtmlEscaped $dd.Line.Trim())</td><td class='text-muted'>ipconfig</td></tr>" } } catch {}
    }
} catch {
    $advProxyRows = "<tr><td colspan='3' class='text-muted'>No se pudo verificar proxy/DNS: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
# Unquoted service path + writable path
try {
    $svcs = Get-CimInstance Win32_Service -ErrorAction Stop
    $unquotedHits = @()
    foreach ($svc in $svcs) {
        $path = $svc.PathName
        if (-not $path) { continue }
        # Unquoted con espacio y sin comillas iniciales
        $isUnquoted = ($path -like "* *" -and $path -notlike '"*"*' -and $path -like "*.exe*")
        $isWritablePath = ($path -like "*\Users\*" -or $path -like "*\Temp\*" -or $path -like "*\AppData\*")
        if ($isUnquoted) {
            $unquotedHits += "<tr class='row-bad'><td>$(ConvertTo-HtmlEscaped $svc.Name)</td><td style='word-break:break-all;'>$(ConvertTo-HtmlEscaped $path)</td><td><span class='badge bad'>Unquoted path</span></td></tr>"; $advBad++
        } elseif ($isWritablePath) {
            $unquotedHits += "<tr class='row-bad'><td>$(ConvertTo-HtmlEscaped $svc.Name)</td><td style='word-break:break-all;'>$(ConvertTo-HtmlEscaped $path)</td><td><span class='badge bad'>Ruta escribible por usuario</span></td></tr>"; $advBad++
        }
    }
    if ($unquotedHits.Count -gt 0) { $advUnquotedRows = ($unquotedHits | Select-Object -First 15) -join ""; if ($unquotedHits.Count -gt 15) { $advUnquotedRows += "<tr><td colspan='3' class='text-muted'>+ $($unquotedHits.Count-15) mas</td></tr>" } }
    else { $advUnquotedRows = "<tr><td colspan='3' class='text-ok'>Sin servicios con unquoted path ni ruta escribible (revisados $($svcs.Count)).</td></tr>" }
} catch {
    $advUnquotedRows = "<tr><td colspan='3' class='text-muted'>No se pudo verificar servicios: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
# Tareas con Temp/AppData
try {
    $tempTasks = @()
    try {
        $allTasks = Get-ScheduledTask -ErrorAction Stop
        foreach ($tsk in $allTasks) {
            foreach ($act in $tsk.Actions) {
                $exe = "$($act.Execute) $($act.Arguments)"
                if ($exe -like "*Temp*" -or $exe -like "*AppData*" -or $exe -like "*\Users\*\Downloads\*") {
                    $tempTasks += "<tr class='row-bad'><td>$(ConvertTo-HtmlEscaped $tsk.TaskName)</td><td>$(ConvertTo-HtmlEscaped $tsk.TaskPath)</td><td style='word-break:break-all;'>$(ConvertTo-HtmlEscaped $exe)</td></tr>"; $advBad++
                }
            }
        }
    } catch {}
    if ($tempTasks.Count -gt 0) { $advTasksTempRows = ($tempTasks | Select-Object -First 15) -join "" } else { $advTasksTempRows = "<tr><td colspan='3' class='text-ok'>Sin tareas con ejecutable en Temp/AppData.</td></tr>" }
} catch {
    $advTasksTempRows = "<tr><td colspan='3' class='text-muted'>Error tareas Temp: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
# Vectores raros: netsh helpers, Lsa Security Packages, Print Processors, Time Providers, BYOVD, BITS
try {
    $rareHits = @()
    # netsh helpers
    try {
        $helpers = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NetSh" -ErrorAction Stop
        foreach ($p in $helpers.PSObject.Properties) {
            if ($p.Name -match "^PS") { continue }
            $rareHits += "<tr><td>NetSh Helper</td><td>$(ConvertTo-HtmlEscaped $p.Name) = $(ConvertTo-HtmlEscaped $p.Value)</td><td><span class='badge warn'>Revisar</span></td></tr>"
        }
    } catch {}
    # Lsa Security Packages
    try {
        $lsa = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction Stop)."Security Packages"
        $known = @("kerberos","msv1_0","schannel","wdigest","tspkg","pku2u")
        foreach ($pkg in $lsa) {
            if ($pkg -and $known -notcontains $pkg.ToLower()) {
                $rareHits += "<tr class='row-bad'><td>Lsa Security Package</td><td>$(ConvertTo-HtmlEscaped $pkg)</td><td><span class='badge bad'>Desconocido (mimikatz?)</span></td></tr>"; $advBad++
            }
        }
    } catch {}
    # Print Processors
    try {
        $procs = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors" -ErrorAction SilentlyContinue
        foreach ($pr in $procs) {
            $drv = (Get-ItemProperty -Path $pr.PSPath -ErrorAction SilentlyContinue).Driver
            if ($drv -and $drv -notlike "*winprint*") {
                $rareHits += "<tr><td>Print Processor</td><td>$(ConvertTo-HtmlEscaped $pr.PSChildName) -> $(ConvertTo-HtmlEscaped $drv)</td><td><span class='badge warn'>Revisar</span></td></tr>"
            }
        }
    } catch {}
    # BITS jobs
    try {
        $bits = Get-BitsTransfer -AllUsers -ErrorAction Stop | Select-Object -First 5
        foreach ($b in $bits) {
            $rareHits += "<tr><td>BITS</td><td>$(ConvertTo-HtmlEscaped $b.DisplayName) -> $(ConvertTo-HtmlEscaped $b.FileList)</td><td><span class='badge warn'>Job activo</span></td></tr>"
        }
    } catch {}
    # Drivers fuera de System32\drivers
    try {
        $drvs = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object { $_.PathName -and $_.PathName -notlike "*\System32\drivers\*" -and $_.PathName -like "*.sys*" } | Select-Object -First 5
        foreach ($d in $drvs) {
            $rareHits += "<tr><td>Driver fuera de System32</td><td>$(ConvertTo-HtmlEscaped $d.Name) -> $(ConvertTo-HtmlEscaped $d.PathName)</td><td><span class='badge warn'>Posible BYOVD</span></td></tr>"
        }
    } catch {}
    if ($rareHits.Count -gt 0) { $advRareRows = ($rareHits -join "") } else { $advRareRows = "<tr><td colspan='3' class='text-ok'>Sin vectores raros detectados (NetSh/Lsa/Print/BITS/BYOVD).</td></tr>" }
} catch {
    $advRareRows = "<tr><td colspan='3' class='text-muted'>Error vectores raros: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
# .lnk resolver Startup
try {
    $lnkHits = @()
    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    )
    foreach ($sp in $startupPaths) {
        if (Test-Path $sp) {
            $lnks = Get-ChildItem -Path $sp -Filter "*.lnk" -ErrorAction SilentlyContinue
            foreach ($lnk in $lnks) {
                try {
                    $sh = New-Object -COM WScript.Shell
                    $target = $sh.CreateShortcut($lnk.FullName).TargetPath
                    $isTemp = ($target -like "*Temp*" -or $target -like "*AppData*")
                    $badge = if ($isTemp) { "bad" } else { "ok" }
                    if ($isTemp) { $advBad++ }
                    $lnkHits += "<tr class='$(if($isTemp){'row-bad'})'><td>$(ConvertTo-HtmlEscaped $lnk.Name)</td><td style='word-break:break-all;'>$(ConvertTo-HtmlEscaped $target)</td><td><span class='badge $badge'>$(if($isTemp){'Temp/AppData -> Revisar'}else{'OK'})</span></td></tr>"
                } catch {}
            }
        }
    }
    if ($lnkHits.Count -gt 0) { $advLnkRows = ($lnkHits -join "") } else { $advLnkRows = "<tr><td colspan='3' class='text-ok'>Sin .lnk sospechosos en Inicio (o sin .lnk).</td></tr>" }
} catch {
    $advLnkRows = "<tr><td colspan='3' class='text-muted'>No se pudo resolver .lnk: $(ConvertTo-HtmlEscaped $_.Exception.Message)</td></tr>"
}
$advSummary = if ($advBad -gt 0) { "$advBad hallazgo(s) en persistencia avanzada" } else { "Sin hallazgos en checklist Autoruns" }
$advBadge = if ($advBad -gt 0) { "bad" } elseif ($advWowRows -match "warn") { "warn" } else { "ok" }

# ----------------------------------------------------
# GENERACION DE HTML (resumen previo)
# ----------------------------------------------------
function Get-BadgeForRow($result) {
    if ($result.IOCMatch) { return "bad" }
    if (-not $result.Exists) { return "warn" }
    if ($result.Mismatch -and $result.Mismatch.Mismatch) { return "bad" }
    return "ok"
}

$auditCardsHtml = ""
foreach ($r in ($auditResults | Sort-Object { (Get-BadgeForRow $_) -eq "ok" })) {
    $badge = Get-BadgeForRow $r
    $cardClass = if ($badge -eq "bad") { "card-bad" } elseif ($badge -eq "warn") { "card-warn" } else { "" }
    $status = if ($r.IOCMatch) {
        "<span class='badge bad'>IOC CONOCIDO</span>"
    } elseif (-not $r.Exists) {
        "<span class='badge warn'>Archivo no encontrado</span>"
    } elseif ($r.Mismatch -and $r.Mismatch.Mismatch) {
        "<span class='badge bad'>Posible masquerading</span>"
    } else {
        "<span class='badge ok'>OK</span>"
    }
    $detail = if ($r.IOCMatch) {
        ConvertTo-HtmlEscaped $r.IOCMatch
    } elseif ($r.Mismatch -and $r.Mismatch.Mismatch) {
        ConvertTo-HtmlEscaped $r.Mismatch.Reason
    } elseif (-not $r.Exists) {
        "Referenciado en autoarranque pero el archivo ya no existe en disco."
    } else {
        "Fabricante coincide con la carpeta contenedora."
    }
    $companyDisplay = if ($r.Company) { ConvertTo-HtmlEscaped $r.Company } else { "(sin metadatos)" }
    $srcEsc = ConvertTo-HtmlEscaped $r.Source
    $nameEsc = ConvertTo-HtmlEscaped $r.Name
    $pathEsc = ConvertTo-HtmlEscaped $r.Path
    $signEsc = ConvertTo-HtmlEscaped $r.SignStatus
    $signerEsc = ConvertTo-HtmlEscaped $r.Signer
    $hashEsc = ConvertTo-HtmlEscaped $r.Hash
    # Resumen corto para el summary: nombre + path (trunc visual via CSS) + status
    $auditCardsHtml += @"
<details class="audit-card $cardClass">
    <summary>
        <span class="audit-summary-left">
            <strong>$nameEsc</strong>
            <span class="audit-path">$pathEsc</span>
        </span>
        <span class="audit-summary-right">$status</span>
    </summary>
    <div class="audit-details">
        <div class="audit-grid">
            <div><span class="label">Origen</span><span class="value">$srcEsc</span></div>
            <div><span class="label">Fabricante</span><span class="value">$companyDisplay</span></div>
            <div><span class="label">Firma</span><span class="value">$signEsc</span></div>
            <div><span class="label">Firmante</span><span class="value" style="word-break:break-all;">$signerEsc</span></div>
        </div>
        <div style="margin-top:8px;">
            <span class="label">Ruta completa</span>
            <code style="word-break:break-all; display:block; margin-top:4px;">$pathEsc</code>
        </div>
        <div style="margin-top:8px;">
            <span class="label">SHA256</span>
            <code style="word-break:break-all; display:block; margin-top:4px;">$hashEsc</code>
        </div>
        <div class="audit-detail-box">$detail</div>
    </div>
</details>
"@
}
if (-not $auditCardsHtml) {
    $auditCardsHtml = "<p class='text-muted'>No se encontraron entradas de autoarranque.</p>"
}

$procRowsHtml = ""
foreach ($p in $topProcs) {
    $pPath = if ($p.Path) { ConvertTo-HtmlEscaped $p.Path } else { "(sin ruta accesible)" }
    $pName = ConvertTo-HtmlEscaped $p.Name
    $delta = [math]::Round($p.CPU,2)
    $pct = if ($null -ne $p.CPU_Pct) { "$($p.CPU_Pct)% (1.2s)" } else { "$delta s" }
    $badge = if ($p.CPU -gt 1) { "warn" } elseif ($p.CPU -gt 5) { "bad" } else { "ok" }
    $procRowsHtml += "<tr><td>$pName</td><td>$($p.Id)</td><td><span class='badge $badge'>$pct</span> ($delta s delta)</td><td>$($p.RAM_MB) MB</td><td style='word-break:break-all;'>$pPath</td></tr>"
}

$iocSummaryHtml = if ($iocHits.Count -gt 0) {
    "<div class='card'><h3 style='color:var(--bad-color);'>[ALERTA] Coincidencias con IOCs conocidos</h3><p>Se encontraron $($iocHits.Count) binario(s) que coinciden con hashes de incidentes previos confirmados. Requiere remediacion inmediata.</p></div>"
} else {
    "<div class='card'><h3 style='color:var(--ok-color);'>Sin coincidencias con IOCs conocidos</h3><p>Ningun binario en autoarranque coincide con hashes documentados.</p></div>"
}

$mismatchSummary = if ($mismatchHits.Count -gt 0) {
    "$($mismatchHits.Count) entrada(s) con fabricante que no coincide con su carpeta - revisar manualmente."
} else {
    "Ninguna discrepancia carpeta/fabricante detectada."
}

$clockBadge = if ($throttleWarning) { "bad" } else { "ok" }
$clockNote = if ($throttleWarning) {
    "La CPU esta operando muy por debajo de su frecuencia base$clockNotePerf. Patron compatible con throttling termico por carga sostenida en segundo plano."
} else {
    "La CPU opera dentro de un rango normal respecto a su frecuencia base$clockNotePerf."
}

$computerEsc = ConvertTo-HtmlEscaped $ComputerName
$cpuNameEsc = ConvertTo-HtmlEscaped $cpu.Name

$htmlContent = @"
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Auditoria de Autoarranque - $computerEsc</title>
    <style>
        :root {
            --bg: #0f172a; --card-bg: #1e293b; --card-border: #334155;
            --text-main: #f8fafc; --text-muted: #94a3b8; --accent-blue: #38bdf8;
            --ok-color: #22c55e; --warn-color: #eab308; --bad-color: #ef4444;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        body { background-color: var(--bg); color: var(--text-main); padding: 24px; line-height: 1.5; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--card-border); padding-bottom: 16px; margin-bottom: 24px; }
        .header h1 { font-size: 24px; color: var(--accent-blue); }
        .header p { color: var(--text-muted); font-size: 14px; }
        .card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 8px; padding: 20px; margin-bottom: 24px; }
        .card h3 { color: var(--accent-blue); margin-bottom: 14px; font-size: 18px; border-bottom: 1px solid var(--card-border); padding-bottom: 8px; }
        .card h4 { color: var(--text-main); margin: 14px 0 8px 0; font-size: 15px; }
        table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }
        th { text-align: left; background: rgba(15, 23, 42, 0.8); color: var(--text-muted); padding: 10px; border-bottom: 1px solid var(--card-border); }
        td { padding: 10px; border-bottom: 1px solid var(--card-border); vertical-align: top; }
        tr:hover { background: rgba(255, 255, 255, 0.02); }
        tr.row-bad { background: rgba(239, 68, 68, 0.1); }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; white-space: nowrap; }
        .badge.ok { background: rgba(34, 197, 94, 0.2); color: var(--ok-color); border: 1px solid var(--ok-color); }
        .badge.warn { background: rgba(234, 179, 8, 0.2); color: var(--warn-color); border: 1px solid var(--warn-color); }
        .badge.bad { background: rgba(239, 68, 68, 0.2); color: var(--bad-color); border: 1px solid var(--bad-color); }
        .text-muted { color: var(--text-muted); }
        .footer { text-align: center; color: var(--text-muted); font-size: 12px; margin-top: 30px; }
        code { background: rgba(255,255,255,0.08); padding: 2px 6px; border-radius: 4px; font-size: 12px; }
        /* Cards details para autoarranque - rutas largas */
        .audit-card { background: rgba(15,23,42,0.6); border: 1px solid var(--card-border); border-radius: 8px; margin-bottom: 10px; overflow: hidden; }
        .audit-card.card-bad { border-color: rgba(239,68,68,0.5); background: rgba(239,68,68,0.08); }
        .audit-card.card-warn { border-color: rgba(234,179,8,0.4); }
        .audit-card summary { list-style: none; display: flex; justify-content: space-between; align-items: center; padding: 12px 14px; cursor: pointer; gap: 12px; }
        .audit-card summary::-webkit-details-marker { display: none; }
        .audit-card summary::before { content: ">"; color: var(--text-muted); margin-right: 6px; transition: transform 0.2s; }
        .audit-card[open] summary::before { transform: rotate(90deg); }
        .audit-summary-left { display: flex; flex-direction: column; min-width: 0; flex: 1; }
        .audit-summary-left strong { font-size: 14px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .audit-path { font-size: 11px; color: var(--text-muted); word-break: break-all; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
        .audit-summary-right { flex-shrink: 0; }
        .audit-details { padding: 12px 14px; border-top: 1px solid var(--card-border); background: rgba(15,23,42,0.4); }
        .audit-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; }
        .audit-grid .label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); display: block; }
        .audit-grid .value { font-size: 13px; word-break: break-all; }
        .audit-detail-box { margin-top: 10px; padding: 8px 10px; border-radius: 6px; background: rgba(255,255,255,0.04); border: 1px solid var(--card-border); font-size: 12px; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>Auditoria de Autoarranque y Masquerading</h1>
            <p>Equipo: <strong>$computerEsc</strong> | Generado el $ReportDate</p>
        </div>
        <div><span class="badge ok">Auditoria completada</span></div>
    </div>

    $(if($oneDriveWarn){"<div class='card' style='border-color: var(--warn-color);'><h3 style='color:var(--warn-color);'>Aviso: Escritorio en OneDrive</h3><p class='text-muted'>Reporte con datos personales en OneDrive - verificar manejo LOPDP.</p></div>"})

    $iocSummaryHtml

    <div class="card">
        <h3>Frecuencia de CPU (Throttling) <span class="badge $clockBadge">$throttleMetric %</span></h3>
        <p>Modelo: $cpuNameEsc</p>
        <p>Frecuencia base: $maxClock MHz | Frecuencia actual: $curClock MHz ($clockPct %) | Perf: $(if($null -ne $perfPct){"$perfPct %"}else{"N/D"})</p>
        <p style="margin-top:8px; color:var(--text-muted); font-size:13px;">$clockNote</p>
    </div>

    <div class="card">
        <h3>Programas en Autoarranque - Fabricante vs. Carpeta ($mismatchSummary)</h3>
        <p class="text-muted" style="font-size:12px; margin-bottom:10px;">Click en cada entrada para ver ruta completa, hash y firmante. Las rutas largas ya no rompen la tabla: se muestran como cards plegables (&lt;details&gt;).</p>
        <div class="audit-list">
            $auditCardsHtml
        </div>
    </div>

    <!-- 5. WMI -->
    <div class="card">
        <h3>Suscripciones WMI - Persistencia sin archivo (T1546.003) <span class="badge $wmiBadge">$wmiBadgeText</span></h3>
        <p class="text-muted" style="font-size:12px; margin-bottom:10px;">Win32_StartupCommand NO muestra esto. Un atacante puede registrar __EventFilter + CommandLineEventConsumer en root/subscription y ejecutar codigo sin archivo en disco.</p>
        <h4>__EventFilter</h4>
        <table><thead><tr><th>Nombre</th><th>Query</th><th>Namespace</th></tr></thead><tbody>$wmiFilterRows</tbody></table>
        <h4>Consumers (CommandLine / ActiveScript)</h4>
        <table><thead><tr><th>Nombre</th><th>Tipo</th><th>Comando / Script</th></tr></thead><tbody>$wmiConsumerRows</tbody></table>
        <h4>Bindings (Filter -&gt; Consumer)</h4>
        <table><thead><tr><th>Filtro</th><th>Consumer</th></tr></thead><tbody>$wmiBindingRows</tbody></table>
    </div>

    <!-- 6. Defender exclusiones -->
    <div class="card">
        <h3>Exclusiones de Windows Defender <span class="badge $exclusionBadge">$defenderExclusionCount exclusion(es)</span></h3>
        <p class="text-muted" style="font-size:12px; margin-bottom:8px;">Si una carpeta como C:\Program Files\WinZip aparece aqui sin intervencion del usuario, es bandera roja. Get-MpPreference ExclusionPath/Process/Extension.</p>
        <table><thead><tr><th>Tipo</th><th>Valor</th><th>Evaluacion</th></tr></thead><tbody>$defenderExclusionRows</tbody></table>
    </div>

    <!-- 7. Red -->
    <div class="card">
        <h3>Conexiones TCP establecidas mapeadas a proceso <span class="badge $tcpBadge">$miningHits puerto(s) minero(s)</span></h3>
        <p class="text-muted" style="font-size:12px; margin-bottom:8px;">Puertos Stratum tipicos 3333,4444,5555,7777,14444. Un minero necesita hablar con el pool; esta es la prueba directa de minado activo.</p>
        <table><thead><tr><th>Proceso</th><th>PID</th><th>Local</th><th>Remoto</th><th>Puerto remoto</th></tr></thead><tbody>$tcpRows</tbody></table>
    </div>

    <!-- 8. Extensiones -->
    <div class="card">
        <h3>Extensiones de navegador <span class="badge $extBadge">$extCount encontrada(s)</span></h3>
        <p class="text-muted" style="font-size:12px; margin-bottom:8px;">Cryptojacking via extension Chrome/Edge es mas comun que binario nativo. Revisa perfiles Default\Extensions.</p>
        <table><thead><tr><th>Ruta extension</th><th>Estado</th></tr></thead><tbody>$extRows</tbody></table>
    </div>

    <!-- 9. StartupApproved -->
    <div class="card">
        <h3>Estado real Habilitado/Deshabilitado (StartupApproved)</h3>
        <p class="text-muted" style="font-size:12px; margin-bottom:8px;">El Administrador de tareas muestra Habilitado/Deshabilitado desde HKCU/HKLM\...\Explorer\StartupApproved. El script ahora distingue lo que el usuario ya desactivo (evita falsos positivos).</p>
        <table><thead><tr><th>Ruta registro</th><th>Nombre</th><th>Estado</th></tr></thead><tbody>$approvedRows</tbody></table>
    </div>

    <!-- 10. IFEO / AppInit -->
    <div class="card">
        <h3>IFEO / AppInit_DLLs (T1546.012 - Hijacking)</h3>
        <p class="text-muted" style="font-size:12px; margin-bottom:8px;">Image File Execution Options puede redirigir notepad.exe u otro binario. AppInit_DLLs inyecta DLL en cada proceso user32.dll.</p>
        <h4>Image File Execution Options</h4>
        <table><thead><tr><th>Ejecutable</th><th>Debugger</th><th>Nota</th></tr></thead><tbody>$ifeoRows</tbody></table>
        <h4>AppInit_DLLs</h4>
        $appInitHtml
    </div>

    <!-- 11. Persistencia avanzada (checklist Autoruns) -->
    <div class="card">
        <h3>Persistencia avanzada - Checklist Autoruns <span class="badge $advBadge">$advSummary</span></h3>
        <p class="text-muted" style="font-size:12px; margin-bottom:10px;">Basado en Sysinternals Autoruns. Cubre vectores modernos que Win32_StartupCommand no ve. Cada sub-tabla es colapsable; badge <span class="badge bad">bad</span> = revisar inmediato.</p>
        <h4>Wow6432Node Run + HKU per-perfil</h4>
        <table><thead><tr><th>Registro</th><th>Nombre</th><th>Valor</th><th>Estado</th></tr></thead><tbody>$advWowRows</tbody></table>
        <h4>Policies Explorer Run (malware)</h4>
        <table><thead><tr><th>Registro</th><th>Nombre</th><th>Valor</th><th>Estado</th></tr></thead><tbody>$advPoliciesRows</tbody></table>
        <h4>COM Hijacking (HKCU Classes CLSID InprocServer32)</h4>
        <table><thead><tr><th>CLSID</th><th>DLL</th><th>Estado</th></tr></thead><tbody>$advComRows</tbody></table>
        <h4>Winlogon Userinit / Shell</h4>
        <table><thead><tr><th>Item</th><th>Valor</th><th>Estado</th></tr></thead><tbody>$advWinlogonRows</tbody></table>
        <h4>Exefile hijack</h4>
        <table><thead><tr><th>Item</th><th>Valor</th><th>Estado</th></tr></thead><tbody>$advExefileRows</tbody></table>
        <h4>Office Add-ins / XLSTART</h4>
        <table><thead><tr><th>Ruta</th><th>Detalle</th><th>Estado</th></tr></thead><tbody>$advOfficeRows</tbody></table>
        <h4>Perfiles PowerShell + historial</h4>
        <table><thead><tr><th>Ruta</th><th>Detalle</th><th>Estado</th></tr></thead><tbody>$advProfileRows</tbody></table>
        <h4>Native Messaging Hosts + Firefox</h4>
        <table><thead><tr><th>Ruta</th><th>Manifest</th><th>Estado</th></tr></thead><tbody>$advNativeRows</tbody></table>
        <h4>Hosts / Proxy / DNS Cache</h4>
        <table><thead><tr><th>Tipo</th><th>Valor</th><th>Estado</th></tr></thead><tbody>$advHostsRows</tbody></table>
        <table><thead><tr><th>Item</th><th>Valor</th><th>Estado</th></tr></thead><tbody>$advProxyRows</tbody></table>
        <h4>Servicios: Unquoted Path / Ruta escribible</h4>
        <table><thead><tr><th>Servicio</th><th>ImagePath</th><th>Estado</th></tr></thead><tbody>$advUnquotedRows</tbody></table>
        <h4>Tareas en Temp/AppData</h4>
        <table><thead><tr><th>Tarea</th><th>Path</th><th>Ejecutable</th></tr></thead><tbody>$advTasksTempRows</tbody></table>
        <h4>Vectores raros (NetSh, LSA, Print, BITS, BYOVD)</h4>
        <table><thead><tr><th>Tipo</th><th>Valor</th><th>Estado</th></tr></thead><tbody>$advRareRows</tbody></table>
        <h4>.lnk en Inicio (WScript.Shell)</h4>
        <table><thead><tr><th>.lnk</th><th>Target</th><th>Estado</th></tr></thead><tbody>$advLnkRows</tbody></table>
    </div>

    <div class="card">
        <h3>Top 10 Procesos por Consumo de CPU (delta 1.2s - uso real)</h3>
        <p class="text-muted" style="font-size:12px; margin-bottom:8px;">Antes se ordenaba por segundos acumulados (el navegador de 3 dias tapaba al minero). Ahora se muestrea con 2 snapshots y delta - evita falsos negativos.</p>
        <table>
            <thead>
                <tr><th>Proceso</th><th>PID</th><th>CPU delta</th><th>RAM</th><th>Ruta</th></tr>
            </thead>
            <tbody>
                $procRowsHtml
            </tbody>
        </table>
    </div>

    <div class="footer">
        Reporte generado automaticamente | Soporte Tecnico e Infraestructura - Christopher Villamarin
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
Write-Host " Reporte generado en: $OutputFile" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Green
try {
    $hash = (Get-FileHash -Path $OutputFile -Algorithm SHA256 -ErrorAction Stop).Hash
    Write-Host " SHA256: $hash" -ForegroundColor Gray
    Add-Content -Path $OutputFile -Value "<!-- SHA256:$hash UTC:$((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'))Z -->" -ErrorAction SilentlyContinue
} catch {}
if (-not $NoOpen) { Start-Process $OutputFile } else { Write-Host " NoOpen: no abierto" -ForegroundColor Gray }
if ($iocHits.Count -gt 0 -or $advBad -gt 0 -or $wmiSuspiciousCount -gt 0) { exit 1 } else { exit 0 }

