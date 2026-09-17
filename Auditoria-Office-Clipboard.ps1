<#
.SYNOPSIS
    Auditoria Office / Excel - Configuracion y diagnostico con reporte HTML.
.DESCRIPTION
    Recopila informacion de configuracion de Office y Excel: version ClickToRun,
    COM Add-ins con LoadBehavior, Resiliency/DisabledItems, aceleracion grafica,
    archivos en XLSTART/STARTUP, procesos en ejecucion, estado de portapapeles,
    eventos 1000/1001/1002 de excel.exe y ajustes de registro.

    Genera reporte HTML portable (CSS inline, sin CDN/JS) en Escritorio o ruta indicada.
    Tambien puede exportar JSON con -AsJson o usarse dot-sourced como modulo.

    Compatible PowerShell 5.1+ (Windows 10/11/Server).
.NOTES
    Sin dependencias externas. No requiere Admin salvo para HKLM Addins y eventos filtrados.
    Si viene de USB/otra PC: Unblock-File -Path .\Auditoria-Office-Clipboard.ps1
    Uso: powershell -ExecutionPolicy Bypass -File .\Auditoria-Office-Clipboard.ps1
#>

#Requires -Version 5.1

param(
    [string]$OutputPath = "",
    [switch]$NoOpen,
    [int]$Days = 14,
    [switch]$AsJson,
    [string]$JsonPath = ""
)

# --- GOTCHAS DE EJECUCION (entornos endurecidos) ---
if ($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage") {
    Write-Host "ADVERTENCIA: LanguageMode=$($ExecutionContext.SessionState.LanguageMode) (no FullLanguage). Algunas secciones fallaran." -ForegroundColor Yellow
}
try {
    $pol = Get-ExecutionPolicy -List -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq "MachinePolicy" }
    if ($pol -and $pol.ExecutionPolicy -ne "Undefined" -and $pol.ExecutionPolicy -ne "Bypass" -and $pol.ExecutionPolicy -ne "Unrestricted") {
        Write-Host "ADVERTENCIA: MachinePolicy=$($pol.ExecutionPolicy) via GPO. Bypass no aplica." -ForegroundColor Yellow
    }
} catch {}
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    $sysNative = "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe"
    $sys64 = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $target = if (Test-Path $sysNative) { $sysNative } else { $sys64 }
    Write-Host "AVISO: Ejecutandose en PowerShell 32-bit en OS 64-bit. Relanzando en 64-bit..." -ForegroundColor Yellow
    try {
        $args2 = @("-ExecutionPolicy","Bypass","-File", $PSCommandPath)
        if ($OutputPath) { $args2 += @("-OutputPath", $OutputPath) }
        if ($NoOpen) { $args2 += "-NoOpen" }
        & $target @args2
        exit $LASTEXITCODE
    } catch { Write-Host "No se pudo relanzar en 64-bit: $($_.Exception.Message)" -ForegroundColor Yellow }
}

$ErrorActionPreference = "SilentlyContinue"

# Helpers comunes del repo
function ConvertTo-HtmlEscaped {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}
function Get-DesktopPathSafe {
    $desktop = [Environment]::GetFolderPath("Desktop")
    if (-not $desktop -or -not (Test-Path $desktop)) { $desktop = "$env:USERPROFILE\Desktop" }
    $isOneDrive = ($desktop -like "*OneDrive*")
    return @{ Path=$desktop; IsOneDrive=$isOneDrive }
}
function Test-PendingReboot {
    $reasons = @()
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") { $reasons += "CBS RebootPending" }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") { $reasons += "WU RebootRequired" }
    try { if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction Stop).PendingFileRenameOperations) { $reasons += "PendingFileRenameOperations" } } catch {}
    return $reasons
}

# ----------------------------------------------------
# 1. FUNCIONES CORE (corregidas respecto al snippet)
# ----------------------------------------------------

function Get-OfficeInfo {
    [CmdletBinding()]
    param()
    $info = [PSCustomObject]@{
        ClickToRun_Config = $null
        ProductReleaseIds = "N/D"
        VersionToReport   = "N/D"
        ClientCulture     = "N/D"
        CDNBaseUrl        = "N/D"
        UpdateChannel     = "N/D"
        Office16_C2R_Path = "N/D"
        OfficeApps        = @()
    }
    try {
        $c2r = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
        if (Test-Path $c2r) {
            $p = Get-ItemProperty -Path $c2r -ErrorAction Stop
            $info.ProductReleaseIds = $p.ProductReleaseIds
            $info.VersionToReport = $p.VersionToReport
            $info.ClientCulture = $p.ClientCulture
            $info.CDNBaseUrl = $p.CDNBaseUrl
            # Inferir canal por CDNBaseUrl
            $url = "$($p.CDNBaseUrl)"
            if ($url -match "492350f6-3a01-4f97-b9c0-c7c6ddf67d60") { $info.UpdateChannel = "Current Channel" }
            elseif ($url -match "64256afe-f5d9-4f86-8936-8840a6a4f5be") { $info.UpdateChannel = "Monthly Enterprise" }
            elseif ($url -match "55336b82-a18d-4dd6-b5f6-9e5095c314a6") { $info.UpdateChannel = "Semi-Annual Enterprise" }
            elseif ($url -match "7ffbc6bf-bc32-4f92-8982-f9dd17fd3114") { $info.UpdateChannel = "Beta/Insider" }
            else { $info.UpdateChannel = $url }
            $info.ClickToRun_Config = $c2r
        }
        # Apps instaladas via Office16
        $officeRoot = "${env:ProgramFiles}\Microsoft Office\root\Office16"
        if (Test-Path $officeRoot) {
            $info.Office16_C2R_Path = $officeRoot
            $exes = @("EXCEL.EXE","WINWORD.EXE","OUTLOOK.EXE","POWERPNT.EXE")
            foreach ($exe in $exes) {
                $fp = Join-Path $officeRoot $exe
                if (Test-Path $fp) {
                    try { $vi = (Get-Item $fp).VersionInfo.FileVersion } catch { $vi = "N/D" }
                    $info.OfficeApps += [PSCustomObject]@{ App=$exe; Path=$fp; Version=$vi }
                }
            }
        }
        # Fallback Office 15 / 14 MSI
        if ($info.OfficeApps.Count -eq 0) {
            $msiPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*")
            foreach ($pat in $msiPaths) {
                try {
                    Get-ItemProperty -Path $pat -ErrorAction SilentlyContinue |
                        Where-Object { $_.DisplayName -like "*Microsoft Office*" -or $_.DisplayName -like "*Microsoft 365*" } |
                        ForEach-Object {
                            $info.OfficeApps += [PSCustomObject]@{ App=$_.DisplayName; Path=$_.InstallLocation; Version=$_.DisplayVersion }
                        }
                } catch {}
            }
        }
    } catch {}
    return $info
}

function Get-ExcelComAddins {
    [CmdletBinding()]
    param()
    $paths = @(
        "HKCU:\Software\Microsoft\Office\Excel\Addins",
        "HKLM:\SOFTWARE\Microsoft\Office\Excel\Addins",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Excel\Addins"
    )
    $results = @()
    foreach ($path in $paths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                $loadBehavior = $props.LoadBehavior
                $status = switch ($loadBehavior) {
                    3       { "Activo (Carga al Inicio)" }
                    2       { "Desactivado (No Cargar)" }
                    1       { "Cargar bajo demanda" }
                    8       { "Cargar bajo demanda (8)" }
                    9       { "Activo bajo demanda (9)" }
                    16      { "Cargar primera vez (16)" }
                    0       { "Desconectado (0)" }
                    default { "Desconocido ($loadBehavior)" }
                }
                $badge = if ($loadBehavior -eq 3) { "warn" } elseif ($loadBehavior -eq 2 -or $loadBehavior -eq 0) { "ok" } else { "warn" }
                $results += [PSCustomObject]@{
                    AddInName    = $_.PSChildName
                    Status       = $status
                    Badge        = $badge
                    LoadBehavior = $loadBehavior
                    Description  = $props.FriendlyName
                    ProgID       = $props.ProgID
                    RegistryPath = $path
                }
            }
        }
    }
    return $results
}

function Get-ExcelResiliency {
    [CmdletBinding()]
    param()
    $rows = @()
    $basePaths = @(
        "HKCU:\Software\Microsoft\Office\16.0\Excel\Resiliency",
        "HKCU:\Software\Microsoft\Office\16.0\Excel\Addins",
        "HKCU:\Software\Microsoft\Office\15.0\Excel\Resiliency"
    )
    # DisabledItems, CrashingAddinList, StartupItems
    $subKeys = @("DisabledItems","CrashingAddinList","StartupItems","NotificationReminderAddinData")
    foreach ($base in $basePaths) {
        foreach ($sub in $subKeys) {
            $full = "$base\$sub"
            # Resiliency tiene sub-estructura distinta
            $checkPaths = @("$base\$sub", "HKCU:\Software\Microsoft\Office\16.0\Excel\Resiliency\$sub")
            foreach ($cp in $checkPaths) {
                if (Test-Path $cp) {
                    try {
                        $items = Get-ChildItem -Path $cp -ErrorAction SilentlyContinue
                        foreach ($it in $items) {
                            $rows += [PSCustomObject]@{ Area=$sub; Name=$it.PSChildName; Path=$cp; Detail="Clave resiliency presente" }
                        }
                        $props = Get-ItemProperty -Path $cp -ErrorAction SilentlyContinue
                        foreach ($p in $props.PSObject.Properties) {
                            if ($p.Name -match "^PS") { continue }
                            $rows += [PSCustomObject]@{ Area=$sub; Name=$p.Name; Path=$cp; Detail=ConvertTo-HtmlEscaped "$($p.Value)" }
                        }
                    } catch {}
                }
            }
        }
    }
    # Metodo directo para DisabledItems que guarda binarios
    $disabledDirect = "HKCU:\Software\Microsoft\Office\16.0\Excel\Resiliency\DisabledItems"
    if (Test-Path $disabledDirect) {
        try {
            $props = Get-ItemProperty -Path $disabledDirect -ErrorAction SilentlyContinue
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -match "^PS") { continue }
                $rows += [PSCustomObject]@{ Area="DisabledItems"; Name=$p.Name; Path=$disabledDirect; Detail="Add-in deshabilitado por Excel tras cuelgue" }
            }
        } catch {}
    }
    return $rows
}

function Get-OfficeGfxAccelerationStatus {
    [CmdletBinding()]
    param()
    $gfxPath = "HKCU:\Software\Microsoft\Office\16.0\Common\Graphics"
    $status = "Habilitada (Por defecto)"
    $rawValue = $null
    $badge = "ok"
    if (Test-Path $gfxPath) {
        $rawValue = (Get-ItemProperty -Path $gfxPath -Name "DisableHardwareAcceleration" -ErrorAction SilentlyContinue).DisableHardwareAcceleration
        if ($rawValue -eq 1) {
            $status = "Deshabilitada por Registro"
            $badge = "warn"
        }
    }
    # Tambien chequear GPO
    $gpoPath = "HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Graphics"
    $gpoVal = $null
    if (Test-Path $gpoPath) {
        $gpoVal = (Get-ItemProperty -Path $gpoPath -Name "DisableHardwareAcceleration" -ErrorAction SilentlyContinue).DisableHardwareAcceleration
        if ($gpoVal -eq 1) { $status += " (GPO fuerza deshabilitado)"; $badge = "warn" }
    }
    return [PSCustomObject]@{
        AceleracionGrafica = $status
        ValorDisableHWAcc  = if ($null -eq $rawValue) { "No configurado" } else { $rawValue }
        ValorGPO           = if ($null -eq $gpoVal) { "No configurado" } else { $gpoVal }
        PathRegistry       = $gfxPath
        Badge              = $badge
    }
}

function Get-ExcelXLSTARTFiles {
    [CmdletBinding()]
    param()
    $xlStartPaths = @(
        "$env:APPDATA\Microsoft\Excel\XLSTART",
        "$env:ProgramFiles\Microsoft Office\root\Office16\XLSTART",
        "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\XLSTART",
        "$env:APPDATA\Microsoft\Word\STARTUP",
        "$env:APPDATA\Microsoft\Excel\XLSTART\PERSONAL.XLSB"
    )
    $files = @()
    foreach ($path in $xlStartPaths) {
        if (Test-Path $path) {
            try {
                $isFile = Test-Path $path -PathType Leaf
                if ($isFile) {
                    $f = Get-Item -Path $path -ErrorAction SilentlyContinue
                    if ($f) {
                        $files += [PSCustomObject]@{
                            FileName      = $f.Name
                            SizeKB        = [math]::Round($f.Length / 1KB, 2)
                            LastWriteTime = $f.LastWriteTime
                            Directory     = $f.DirectoryName
                            Suspicious    = ($f.Extension -match "\.(xlam|xla|dotm)" -or $f.Name -like "PERSONAL*")
                        }
                    }
                } else {
                    Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                        $files += [PSCustomObject]@{
                            FileName      = $_.Name
                            SizeKB        = [math]::Round($_.Length / 1KB, 2)
                            LastWriteTime = $_.LastWriteTime
                            Directory     = $_.DirectoryName
                            Suspicious    = ($_.Extension -match "\.(xlam|xla|dotm)" -or $_.Name -like "PERSONAL*")
                        }
                    }
                }
            } catch {}
        }
    }
    return $files
}

function Get-ExcelHangEvents {
    [CmdletBinding()]
    param(
        [int]$Days = 14
    )
    $events = @()
    try {
        $filter = @{
            LogName   = 'Application'
            ID        = 1000, 1001, 1002
            StartTime = (Get-Date).AddDays(-$Days)
        }
        $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop |
            Where-Object { $_.Message -like "*excel.exe*" -or $_.Message -like "*EXCEL.EXE*" -or $_.ProviderName -like "*Application Hang*" -or $_.ProviderName -like "*Application Error*" } |
            Select-Object -First 15 |
            ForEach-Object {
                $type = switch ($_.Id) {
                    1002 { "Application Hang (Colgado)" }
                    1001 { "Windows Error Reporting" }
                    default { "Application Crash (Fallo)" }
                }
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    EventID     = $_.Id
                    EventType   = $type
                    Provider    = $_.ProviderName
                    Summary     = (($_.Message -split "`r?`n")[0]).Substring(0, [math]::Min(300, (($_.Message -split "`r?`n")[0]).Length))
                }
            }
    } catch {
        # Se ignora si no existen eventos en el rango
    }
    # Fallback: si Get-WinEvent falla por permisos, intentar filtrado mas laxo
    if ($events.Count -eq 0) {
        try {
            $events = Get-WinEvent -FilterHashtable @{ LogName='Application'; StartTime=(Get-Date).AddDays(-$Days) } -ErrorAction Stop |
                Where-Object { $_.Id -in @(1000,1001,1002) -and $_.Message -like "*excel*" } |
                Select-Object -First 5 |
                ForEach-Object {
                    [PSCustomObject]@{
                        TimeCreated = $_.TimeCreated
                        EventID     = $_.Id
                        EventType   = "Office Hang/Crash"
                        Provider    = $_.ProviderName
                        Summary     = (($_.Message -split "`r?`n")[0])
                    }
                }
        } catch {}
    }
    return $events
}

function Get-ClipboardHookProcesses {
    [CmdletBinding()]
    param()
    $knownInterceptors = @(
        "PowerToys", "PowerToys.FancyZones", "PowerToys.ClipboardManager",
        "AutoHotkey", "AutoHotkey64", "ShareX", "Greenshot", "Lightshot",
        "Grammarly", "DeepL", "AcroRd32", "Acrobat", "Ditto", "ClipClip", "RazerSynapse",
        "ClipboardFusion", "1Clipboard", "ClipX", "CopyQ", "PhraseExpress",
        "Evernote", "Notion", "Slack", "Teams", "ms-teams", "Zoom", "Webexmta",
        "KeePass", "Bitwarden", "LastPass", "RdpClip", "rdpclip",
        "ClipboardHelpAndSpell", "ArsClip", "Clipdiary", "ComfortClipboard"
    )
    $found = @()
    try {
        Get-Process -ErrorAction SilentlyContinue |
            Where-Object { $knownInterceptors -contains $_.ProcessName } |
            ForEach-Object {
                $st2 = "N/D"
                try { $st2 = $_.StartTime } catch {}
                $found += [PSCustomObject]@{
                    ProcessName = $_.ProcessName
                    PID         = $_.Id
                    Path        = $_.Path
                    StartTime   = $st2
                }
            }
    } catch {}
    # Tambien verificar rdpclip en sesion RDP
    try {
        $rdp = Get-Process -Name "rdpclip" -ErrorAction SilentlyContinue
        if ($rdp -and -not ($found | Where-Object { $_.ProcessName -eq "rdpclip" })) {
            foreach ($p in $rdp) {
                $st3 = "N/D"
                try { $st3 = $p.StartTime } catch {}
                $found += [PSCustomObject]@{ ProcessName=$p.ProcessName; PID=$p.Id; Path=$p.Path; StartTime=$st3 }
            }
        }
    } catch {}
    return $found
}

function Test-ClipboardHealth {
    [CmdletBinding()]
    param()
    $result = [PSCustomObject]@{
        CanOpenClipboard = "No probado"
        SequenceNumber   = "N/D"
        OwnerPID         = "N/D"
        OwnerProcess     = "N/D"
        Formats          = "N/D"
        Preview          = "N/D"
        Error            = ""
        Badge            = "warn"
    }
    # Intento 1: Get-Clipboard nativo
    try {
        $txt = Get-Clipboard -ErrorAction Stop
        if ($null -ne $txt) {
            $preview = "$txt"
            if ($preview.Length -gt 80) { $preview = $preview.Substring(0,80) + "..." }
            $result.Preview = $preview
        } else {
            $result.Preview = "(vacio o no texto)"
        }
    } catch {
        $result.Error = $_.Exception.Message
        $result.Preview = "Error Get-Clipboard: $($_.Exception.Message)"
    }
    # Intento 2: Win32 API para diagnostico profundo
    try {
        Add-Type @"
using System;
using System.Runtime.InteropServices;
public class ClipDiag {
    [DllImport("user32.dll")] public static extern bool OpenClipboard(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool CloseClipboard();
    [DllImport("user32.dll")] public static extern uint GetClipboardSequenceNumber();
    [DllImport("user32.dll")] public static extern IntPtr GetClipboardOwner();
    [DllImport("user32.dll")] public static extern uint GetClipboardOwnerProcessId(IntPtr hWnd, out uint pid);
    [DllImport("user32.dll")] public static extern IntPtr GetOpenClipboardWindow();
}
"@ -ErrorAction SilentlyContinue
        $seq = [ClipDiag]::GetClipboardSequenceNumber()
        $result.SequenceNumber = "$seq"
        $owner = [ClipDiag]::GetClipboardOwner()
        if ($owner -ne [IntPtr]::Zero) {
            try {
                $pidOut = [uint32]0
                # GetWindowThreadProcessId es mas fiable que GetClipboardOwner
                Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32Pid {
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
}
"@ -ErrorAction SilentlyContinue
                $tid = [Win32Pid]::GetWindowThreadProcessId($owner, [ref]$pidOut)
                $result.OwnerPID = "$pidOut"
                try { $proc = Get-Process -Id $pidOut -ErrorAction Stop; $result.OwnerProcess = "$($proc.ProcessName) ($pidOut)" } catch { $result.OwnerProcess = "PID $pidOut (no resuelto)" }
            } catch {
                $result.OwnerProcess = "Owner handle: $owner"
            }
        } else {
            $result.OwnerProcess = "(ningun owner - clipboard libre)"
            $result.OwnerPID = "0"
        }
        $opened = [ClipDiag]::OpenClipboard([IntPtr]::Zero)
        if ($opened) {
            [void][ClipDiag]::CloseClipboard()
            $result.CanOpenClipboard = "Si (OpenClipboard OK)"
            $result.Badge = "ok"
        } else {
            $result.CanOpenClipboard = "No - bloqueado por otro proceso"
            $result.Badge = "bad"
        }
    } catch {
        $result.Error += " | API: $($_.Exception.Message)"
        $result.CanOpenClipboard = "Error API: $($_.Exception.Message)"
        $result.Badge = "warn"
    }
    # Formatos disponibles
    try {
        $formats = Get-Clipboard -Format Image -ErrorAction SilentlyContinue
        if ($formats) { $result.Formats = "Texto + Imagen disponible" }
        else { $result.Formats = "Texto (o vacio) - Get-Clipboard OK" }
    } catch {
        $result.Formats = "No determinado"
    }
    # Clipboard history (Windows 10+)
    try {
        $hist = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -ErrorAction SilentlyContinue).EnableClipboardHistory
        if ($hist -eq 1) { $result.Formats += " | Historial activado" }
        elseif ($hist -eq 0) { $result.Formats += " | Historial desactivado" }
    } catch {}
    return $result
}

function Get-ExcelRegistryTweaks {
    [CmdletBinding()]
    param()
    $checks = @()
    $map = @(
        @{ Path="HKCU:\Software\Microsoft\Office\16.0\Excel\Options"; Name="QFE_Support"; Expected="N/D"; Desc="Parches Excel" },
        @{ Path="HKCU:\Software\Microsoft\Office\16.0\Common"; Name="Debug"; Expected="N/D"; Desc="Debug Office" },
        @{ Path="HKCU:\Software\Microsoft\Office\16.0\Excel\Security"; Name="VBAWarnings"; Expected="N/D"; Desc="Seguridad macros" },
        @{ Path="HKCU:\Software\Microsoft\Office\16.0\Excel\Options"; Name="AutoRecoverPath"; Expected="N/D"; Desc="Ruta AutoRecover" },
        @{ Path="HKCU:\Software\Microsoft\Office\16.0\Common\Graphics"; Name="DisableHardwareAcceleration"; Expected="0 o no existe"; Desc="Aceleracion HW (ver seccion dedicada)" },
        @{ Path="HKCU:\Control Panel\Desktop"; Name="DragFullWindows"; Expected="N/D"; Desc="Arrastrar ventanas" }
    )
    foreach ($m in $map) {
        $val = $null
        $exists = $false
        if (Test-Path $m.Path) {
            try { $val = (Get-ItemProperty -Path $m.Path -Name $m.Name -ErrorAction Stop).$($m.Name); $exists = $true } catch {}
        }
        $checks += [PSCustomObject]@{
            Path = $m.Path
            Name = $m.Name
            Value = if ($exists) { "$val" } else { "(no configurado)" }
            Desc = $m.Desc
        }
    }
    # DDE y Opciones de compatibilidad
    try {
        $dde = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Options" -Name "DDEAllowed" -ErrorAction SilentlyContinue).DDEAllowed
        if ($null -ne $dde) { $checks += [PSCustomObject]@{ Path="HKCU:\...\Excel\Options"; Name="DDEAllowed"; Value="$dde"; Desc="DDE permitido" } }
    } catch {}
    # ProtectedView
    try {
        $pv = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView" -ErrorAction SilentlyContinue
        if ($pv) {
            foreach ($p in $pv.PSObject.Properties) {
                if ($p.Name -match "^PS") { continue }
                $checks += [PSCustomObject]@{ Path="ProtectedView"; Name=$p.Name; Value="$($p.Value)"; Desc="Vista protegida" }
            }
        }
    } catch {}
    return $checks
}

function Get-ExcelRunningState {
    [CmdletBinding()]
    param()
    $procs = @()
    try {
        $procs = Get-Process -Name "EXCEL" -ErrorAction SilentlyContinue | ForEach-Object {
            $cpuVal = "N/D"
            try { $cpuVal = [math]::Round($_.CPU,2) } catch {}
            $st = "N/D"
            try { $st = $_.StartTime } catch {}
            [PSCustomObject]@{
                PID = $_.Id
                CPU = $cpuVal
                RAM_MB = [math]::Round($_.WorkingSet / 1MB, 1)
                Handles = $_.HandleCount
                StartTime = $st
                Responding = $_.Responding
            }
        }
    } catch {}
    return $procs
}

function Invoke-OfficeAudit {
    [CmdletBinding()]
    param(
        [switch]$AsJson,
        [int]$Days = 14
    )
    $report = [PSCustomObject]@{
        AuditTimestamp       = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        HostName             = $env:COMPUTERNAME
        UserName             = $env:USERNAME
        OfficeInfo           = Get-OfficeInfo
        HardwareAcceleration = Get-OfficeGfxAccelerationStatus
        ComAddins            = Get-ExcelComAddins
        Resiliency           = Get-ExcelResiliency
        XLSTARTFiles         = Get-ExcelXLSTARTFiles
        HookProcesses        = Get-ClipboardHookProcesses
        ClipboardHealth      = Test-ClipboardHealth
        ExcelRegistry        = Get-ExcelRegistryTweaks
        ExcelProcesses       = Get-ExcelRunningState
        RecentExcelHangLogs  = Get-ExcelHangEvents -Days $Days
        PendingReboot        = Test-PendingReboot
    }
    if ($AsJson) {
        return ($report | ConvertTo-Json -Depth 6)
    }
    return $report
}

# ----------------------------------------------------
# EJECUCION PRINCIPAL
# ----------------------------------------------------
$ReportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ComputerName = $env:COMPUTERNAME
$desktopInfo = Get-DesktopPathSafe
$desktopPath = $desktopInfo.Path
$oneDriveWarn = $desktopInfo.IsOneDrive

# Si se importa como modulo (. .\Auditoria-Office-Clipboard.ps1), no generar HTML
# Solo generar si se ejecuta directo
$isDotSourced = $false
try { $isDotSourced = ($MyInvocation.InvocationName -eq '.' -or $MyInvocation.Line -like ".*\. *\.*") } catch {}

# Soporte -AsJson rapido (si se paso como param y se ejecuta directo)
if ($AsJson -and -not $isDotSourced) {
    $json = Invoke-OfficeAudit -AsJson -Days $Days
    if ($JsonPath) {
        $json | Out-File -FilePath $JsonPath -Encoding utf8 -Force
        Write-Host "JSON exportado a $JsonPath" -ForegroundColor Green
    } else {
        Write-Output $json
    }
    return
}

# Recoleccion para HTML (auto-ejecuta aun sin params, como snippet original)
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " Auditoria Office - $ComputerName" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

Write-Host "[1/10] Info de Office (ClickToRun / MSI)..." -ForegroundColor Yellow
$officeInfo = Get-OfficeInfo
Write-Host "[2/10] COM Add-ins Excel..." -ForegroundColor Yellow
$addins = Get-ExcelComAddins
Write-Host "[3/10] Resiliency / DisabledItems..." -ForegroundColor Yellow
$resiliency = Get-ExcelResiliency
Write-Host "[4/10] Aceleracion grafica..." -ForegroundColor Yellow
$gfx = Get-OfficeGfxAccelerationStatus
Write-Host "[5/10] Archivos XLSTART/STARTUP..." -ForegroundColor Yellow
$xlFiles = Get-ExcelXLSTARTFiles
Write-Host "[6/10] Procesos en ejecucion..." -ForegroundColor Yellow
$hooks = Get-ClipboardHookProcesses
Write-Host "[7/10] Estado de portapapeles..." -ForegroundColor Yellow
$clipHealth = Test-ClipboardHealth
Write-Host "[8/10] Registro Excel / ProtectedView..." -ForegroundColor Yellow
$regTweaks = Get-ExcelRegistryTweaks
Write-Host "[9/10] Procesos Excel en ejecucion..." -ForegroundColor Yellow
$excelProcs = Get-ExcelRunningState
Write-Host "[10/10] Eventos de cuelgue Excel (ultimos $Days dias)..." -ForegroundColor Yellow
$hangs = Get-ExcelHangEvents -Days $Days
$pending = Test-PendingReboot

# Report object para HTML
$report = [PSCustomObject]@{
    OfficeInfo = $officeInfo
    Gfx = $gfx
    Addins = $addins
    Resiliency = $resiliency
    XLSTART = $xlFiles
    Hooks = $hooks
    ClipHealth = $clipHealth
    RegTweaks = $regTweaks
    ExcelProcs = $excelProcs
    Hangs = $hangs
    Pending = $pending
}

# Si fue dot-sourced, exponer objeto y salir sin HTML
if ($isDotSourced) {
    Write-Host "Cargado como modulo. Usa: Invoke-OfficeAudit -AsJson | Out-File office_audit.json" -ForegroundColor Gray
    return $report
}

# ----------------------------------------------------
# CONSTRUCCION HTML
# ----------------------------------------------------
$pendingRows = ""
if ($pending.Count -gt 0) {
    $txt = ConvertTo-HtmlEscaped ($pending -join ", ")
    $pendingRows = "<tr class='row-bad'><td>Reboot pendiente</td><td>$txt</td><td><span class='badge bad'>Reinicio requerido</span></td></tr>"
} else {
    $pendingRows = "<tr><td>Reboot pendiente</td><td>Ninguno</td><td><span class='badge ok'>OK</span></td></tr>"
}

# Office info rows
$officeRows = ""
if ($officeInfo.OfficeApps.Count -gt 0) {
    foreach ($app in $officeInfo.OfficeApps) {
        $aName = ConvertTo-HtmlEscaped $app.App
        $aVer = ConvertTo-HtmlEscaped $app.Version
        $aPath = ConvertTo-HtmlEscaped $app.Path
        $officeRows += "<tr><td>$aName</td><td>$aVer</td><td style='word-break:break-all;'>$aPath</td></tr>"
    }
} else {
    $officeRows = "<tr><td colspan='3' class='text-muted'>No se detecto instalacion Office via ClickToRun ni MSI (posible portable/Microsoft Store).</td></tr>"
}
$officeVerEsc = ConvertTo-HtmlEscaped $officeInfo.VersionToReport
$officeChanEsc = ConvertTo-HtmlEscaped $officeInfo.UpdateChannel
$officeProdEsc = ConvertTo-HtmlEscaped $officeInfo.ProductReleaseIds

# Add-ins rows
$addinRows = ""
$addinBad = 0
if ($addins.Count -gt 0) {
    foreach ($ad in $addins) {
        $cls = if ($ad.Badge -eq "bad") { "row-bad" } else { "" }
        if ($ad.Badge -eq "bad") { $addinBad++ }
        $nEsc = ConvertTo-HtmlEscaped $ad.AddInName
        $sEsc = ConvertTo-HtmlEscaped $ad.Status
        $dEsc = ConvertTo-HtmlEscaped $ad.Description
        $pEsc = ConvertTo-HtmlEscaped $ad.RegistryPath
        $lb = $ad.LoadBehavior
        $badgeCls = $ad.Badge
        $addinRows += "<tr class='$cls'><td>$nEsc</td><td><span class='badge $badgeCls'>$sEsc</span></td><td>$lb</td><td>$dEsc</td><td style='word-break:break-all;'>$pEsc</td></tr>"
    }
} else {
    $addinRows = "<tr><td colspan='5' class='text-ok'>Sin COM Add-ins registrados en Excel (limpio).</td></tr>"
}

# Resiliency rows
$resRows = ""
if ($resiliency.Count -gt 0) {
    foreach ($r in $resiliency) {
        $aEsc = ConvertTo-HtmlEscaped $r.Area
        $nEsc = ConvertTo-HtmlEscaped $r.Name
        $pEsc = ConvertTo-HtmlEscaped $r.Path
        $dEsc = ConvertTo-HtmlEscaped $r.Detail
        $resRows += "<tr class='row-bad'><td>$aEsc</td><td>$nEsc</td><td style='word-break:break-all;'>$pEsc</td><td>$dEsc</td></tr>"
    }
} else {
    $resRows = "<tr><td colspan='4' class='text-ok'>Sin entradas en Resiliency/DisabledItems (Excel no ha deshabilitado add-ins por cuelgue).</td></tr>"
}

# XLSTART rows
$xlRows = ""
if ($xlFiles.Count -gt 0) {
    foreach ($f in $xlFiles) {
        $cls = if ($f.Suspicious) { "row-bad" } else { "" }
        $badge = if ($f.Suspicious) { "<span class='badge bad'>Revisar</span>" } else { "<span class='badge ok'>OK</span>" }
        $fnEsc = ConvertTo-HtmlEscaped $f.FileName
        $dirEsc = ConvertTo-HtmlEscaped $f.Directory
        $xlRows += "<tr class='$cls'><td>$fnEsc</td><td>$($f.SizeKB) KB</td><td>$($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))</td><td style='word-break:break-all;'>$dirEsc</td><td>$badge</td></tr>"
    }
} else {
    $xlRows = "<tr><td colspan='5' class='text-ok'>XLSTART/STARTUP vacio (correcto si no usas PERSONAL.XLSB).</td></tr>"
}

# Hooks rows
$hookRows = ""
$hookBad = 0
if ($hooks.Count -gt 0) {
    foreach ($h in $hooks) {
        $hookBad++
        $pnEsc = ConvertTo-HtmlEscaped $h.ProcessName
        $pathEsc = ConvertTo-HtmlEscaped $h.Path
        $hookRows += "<tr class='row-bad'><td><strong>$pnEsc</strong></td><td>$($h.PID)</td><td style='word-break:break-all;'>$pathEsc</td><td><span class='badge bad'>En ejecucion</span></td></tr>"
    }
} else {
    $hookRows = "<tr><td colspan='4' class='text-ok'>Ningun proceso de la lista en ejecucion.</td></tr>"
}

# Clipboard health
$clipBadge = $clipHealth.Badge
$clipOpenEsc = ConvertTo-HtmlEscaped $clipHealth.CanOpenClipboard
$clipSeqEsc = ConvertTo-HtmlEscaped $clipHealth.SequenceNumber
$clipOwnerEsc = ConvertTo-HtmlEscaped $clipHealth.OwnerProcess
$clipPrevEsc = ConvertTo-HtmlEscaped $clipHealth.Preview
$clipFmtEsc = ConvertTo-HtmlEscaped $clipHealth.Formats
$clipErrEsc = ConvertTo-HtmlEscaped $clipHealth.Error
$clipCardClass = if ($clipBadge -eq "bad") { "card-bad" } elseif ($clipBadge -eq "ok") { "card-ok" } else { "" }

# Registry tweaks rows
$regRows = ""
foreach ($rv in $regTweaks) {
    $pEsc = ConvertTo-HtmlEscaped $rv.Path
    $nEsc = ConvertTo-HtmlEscaped $rv.Name
    $vEsc = ConvertTo-HtmlEscaped $rv.Value
    $dEsc = ConvertTo-HtmlEscaped $rv.Desc
    $regRows += "<tr><td style='word-break:break-all;'>$pEsc</td><td>$nEsc</td><td>$vEsc</td><td>$dEsc</td></tr>"
}
if (-not $regRows) { $regRows = "<tr><td colspan='4' class='text-muted'>Sin datos de registro Excel.</td></tr>" }

# Excel procs rows
$excelRows = ""
if ($excelProcs.Count -gt 0) {
    foreach ($ep in $excelProcs) {
        $respBadge = if ($ep.Responding) { "ok" } else { "bad" }
        $respText = if ($ep.Responding) { "Responde" } else { "No responde (colgado)" }
        $excelRows += "<tr><td>$($ep.PID)</td><td>$($ep.CPU)</td><td>$($ep.RAM_MB) MB</td><td>$($ep.Handles)</td><td><span class='badge $respBadge'>$respText</span></td></tr>"
    }
} else {
    $excelRows = "<tr><td colspan='5' class='text-muted'>Excel no esta en ejecucion ahora (normal si se cerro tras el fallo).</td></tr>"
}

# Hang rows
$hangRows = ""
if ($hangs.Count -gt 0) {
    foreach ($hg in $hangs) {
        $cls = if ($hg.EventID -eq 1002) { "row-bad" } else { "" }
        $provEsc = ConvertTo-HtmlEscaped $hg.Provider
        $typeEsc = ConvertTo-HtmlEscaped $hg.EventType
        $sumEsc = ConvertTo-HtmlEscaped $hg.Summary
        $hangRows += "<tr class='$cls'><td>$($hg.TimeCreated.ToString('MM-dd HH:mm'))</td><td>$provEsc</td><td>$($hg.EventID)</td><td>$typeEsc</td><td>$sumEsc</td></tr>"
    }
} else {
    $hangRows = "<tr><td colspan='5' class='text-ok'>Sin cuelgues/crashes de Excel en los ultimos $Days dias (Eventos 1000/1001/1002).</td></tr>"
}

# GFX detail
$gfxBadge = $gfx.Badge
$gfxStatusEsc = ConvertTo-HtmlEscaped $gfx.AceleracionGrafica
$gfxValEsc = ConvertTo-HtmlEscaped $gfx.ValorDisableHWAcc
$gfxGpoEsc = ConvertTo-HtmlEscaped $gfx.ValorGPO

# Semaphores
$totalBad = $addinBad + $hookBad + (&{ if($clipBadge -eq "bad"){1}else{0} }) + (&{ if($hangs.Count -gt 0){1}else{0} })
$globalBadge = if ($totalBad -eq 0) { "ok" } elseif ($totalBad -le 2) { "warn" } else { "bad" }
$globalText = if ($totalBad -eq 0) { "Sin hallazgos criticos" } elseif ($totalBad -le 2) { "$totalBad hallazgo(s) - revisar" } else { "$totalBad hallazgos - accion recomendada" }

if ($OutputPath) { $OutputFile = $OutputPath } else { $OutputFile = Join-Path $desktopPath ("Auditoria_Office_${ComputerName}_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".html") }

$computerEsc = ConvertTo-HtmlEscaped $ComputerName
$userEsc = ConvertTo-HtmlEscaped $env:USERNAME

$htmlContent = @"
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte Office - $computerEsc</title>
    <style>
        :root { --bg:#0f172a; --card-bg:#1e293b; --card-border:#334155; --text-main:#f8fafc; --text-muted:#94a3b8; --accent-blue:#38bdf8; --ok-color:#22c55e; --warn-color:#eab308; --bad-color:#ef4444; }
        * { box-sizing:border-box; margin:0; padding:0; font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        body { background-color:var(--bg); color:var(--text-main); padding:24px; line-height:1.5; }
        .header { display:flex; justify-content:space-between; align-items:center; border-bottom:2px solid var(--card-border); padding-bottom:16px; margin-bottom:24px; flex-wrap:wrap; gap:12px; }
        .header h1 { font-size:22px; color:var(--accent-blue); }
        .header p { color:var(--text-muted); font-size:13px; }
        .grid-summary { display:grid; grid-template-columns:repeat(auto-fit, minmax(210px, 1fr)); gap:16px; margin-bottom:24px; }
        .summary-card { background:var(--card-bg); border:1px solid var(--card-border); border-radius:8px; padding:16px; }
        .summary-card span.label { font-size:11px; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.5px; display:block; margin-bottom:4px; }
        .summary-card div.val { font-size:17px; font-weight:bold; }
        .card { background:var(--card-bg); border:1px solid var(--card-border); border-radius:8px; padding:20px; margin-bottom:24px; }
        .card.card-bad { border-color:var(--bad-color); }
        .card.card-ok { border-color:var(--ok-color); }
        .card h3 { color:var(--accent-blue); margin-bottom:14px; font-size:17px; border-bottom:1px solid var(--card-border); padding-bottom:8px; }
        .card h4 { color:var(--text-muted); font-size:14px; margin:12px 0 6px 0; }
        table { width:100%; border-collapse:collapse; margin-top:8px; font-size:13px; }
        th { text-align:left; background:rgba(15,23,42,0.8); color:var(--text-muted); padding:8px; border-bottom:1px solid var(--card-border); }
        td { padding:8px; border-bottom:1px solid var(--card-border); }
        tr:hover { background:rgba(255,255,255,0.02); }
        tr.row-bad { background:rgba(239,68,68,0.08); }
        .badge { display:inline-block; padding:3px 9px; border-radius:12px; font-size:11px; font-weight:bold; }
        .badge.ok { background:rgba(34,197,94,0.2); color:var(--ok-color); border:1px solid var(--ok-color); }
        .badge.warn { background:rgba(234,179,8,0.2); color:var(--warn-color); border:1px solid var(--warn-color); }
        .badge.bad { background:rgba(239,68,68,0.2); color:var(--bad-color); border:1px solid var(--bad-color); }
        .text-ok { color:var(--ok-color); }
        .text-muted { color:var(--text-muted); }
        .rec-box { background:rgba(56,189,248,0.08); border:1px solid rgba(56,189,248,0.3); border-radius:6px; padding:12px; margin-top:12px; font-size:13px; }
        .rec-box.bad { background:rgba(239,68,68,0.08); border-color:var(--bad-color); }
        .footer { text-align:center; color:var(--text-muted); font-size:11px; margin-top:30px; }
        code { background:rgba(255,255,255,0.08); padding:2px 5px; border-radius:4px; font-size:12px; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>Auditoria Office / Excel</h1>
            <p>Equipo: <strong>$computerEsc</strong> | Usuario: <strong>$userEsc</strong> | Fecha: $ReportDate | Rango eventos: $Days dias</p>
        </div>
        <div><span class="badge $globalBadge">$globalText</span></div>
    </div>

    $(if($oneDriveWarn){"<div class='card' style='border-color:var(--warn-color);'><h3 style='color:var(--warn-color);'>Aviso: Escritorio en OneDrive</h3><p class='text-muted'>El reporte contiene rutas y procesos y se guardara en OneDrive sincronizado. Verifica retencion.</p></div>"})

    <div class="grid-summary">
        <div class="summary-card"><span class="label">Office Version</span><div class="val">$officeVerEsc</div><p style="font-size:11px;color:var(--text-muted);">Canal: $officeChanEsc</p><p style="font-size:11px;color:var(--text-muted);">Prod: $officeProdEsc</p></div>
        <div class="summary-card"><span class="label">Aceleracion Grafica</span><div class="val"><span class="badge $gfxBadge">$gfxStatusEsc</span></div><p style="font-size:11px;color:var(--text-muted);">DisableHWAcc=$gfxValEsc | GPO=$gfxGpoEsc</p></div>
        <div class="summary-card"><span class="label">COM Add-ins</span><div class="val">$($addins.Count) detectados</div><span class="badge $(if($addinBad -gt 0){'warn'}else{'ok'})">$(if($addinBad -gt 0){"$addinBad activos"}else{"OK"})</span></div>
        <div class="summary-card"><span class="label">Portapapeles</span><div class="val"><span class="badge $clipBadge">$clipOpenEsc</span></div><p style="font-size:11px;color:var(--text-muted);">Owner: $clipOwnerEsc</p></div>
    </div>

    <div class="card $(if($hookBad -gt 0){'card-bad'}else{''})">
        <h3>Diagnostico Rapido - Copiar varias celdas</h3>
        <div class="rec-box $(if($hookBad -gt 0 -or $clipBadge -eq 'bad'){'bad'}else{''})">
            <strong>Causas mas probables (en orden):</strong>
            <ol style="margin:8px 0 0 18px;">
                <li><strong>Programa en ejecucion</strong> tras copiar (ver tabla procesos). Si arriba ves 1+ procesos, cierra ese programa y vuelve a probar.</li>
                <li><strong>COM Add-in en mal estado</strong> - LoadBehavior 3 con cuelgues recientes (ver tabla Add-ins + eventos 1002 Hang). Deshabilita desde Excel &gt; Opciones &gt; Complementos &gt; COM.</li>
                <li><strong>Aceleracion grafica</strong> - Si Excel se cuelga al copiar rangos grandes, desactivala: Archivo &gt; Opciones &gt; Avanzado &gt; Mostrar &gt; Deshabilitar aceleracion grafica de hardware (equivale a <code>DisableHardwareAcceleration=1</code>).</li>
                <li><strong>Archivo en XLSTART/PERSONAL.XLSB</strong> relacionado con inicio automatico.</li>
                <li><strong>Portapapeles no disponible</strong> - <code>CanOpenClipboard=No</code> indica otro proceso con portapapeles abierto sin cerrar. Reinicia Excel.</li>
                <li><strong>RDP</strong> - Si estas en Escritorio Remoto, ejecuta <code>taskkill /f /im rdpclip.exe &amp;&amp; rdpclip.exe</code> en el remoto.</li>
            </ol>
            <p style="margin-top:10px;">Prueba de descarte: abre Excel en modo seguro (<code>excel /safe</code>) y copia el mismo rango. Si ahi funciona, es un Add-in o XLSTART.</p>
        </div>
    </div>

    <div class="card">
        <h3>1. Office Instalado</h3>
        <table><thead><tr><th>App / Producto</th><th>Version</th><th>Ruta / InstallLocation</th></tr></thead><tbody>$officeRows</tbody></table>
        <p class="text-muted" style="font-size:11px; margin-top:6px;">ClickToRun Configuration: $(ConvertTo-HtmlEscaped $officeInfo.ClickToRun_Config) | CDN: $(ConvertTo-HtmlEscaped $officeInfo.CDNBaseUrl)</p>
    </div>

    <div class="card $(if($addinBad -gt 0){'card-bad'}else{''})">
        <h3>2. COM Add-ins de Excel (LoadBehavior)</h3>
        <table><thead><tr><th>Nombre</th><th>Estado</th><th>LoadBehavior</th><th>Descripcion</th><th>Registro</th></tr></thead><tbody>$addinRows</tbody></table>
        <p class="text-muted" style="font-size:11px; margin-top:6px;">3=Activo al inicio (sospechoso si cuelga), 2=Desactivado, 0=Desconectado. Revisa tambien Resiliency abajo.</p>
    </div>

    <div class="card $(if($resiliency.Count -gt 0){'card-bad'}else{''})">
        <h3>3. Resiliency / DisabledItems (Excel deshabilito tras cuelgue)</h3>
        <table><thead><tr><th>Area</th><th>Nombre</th><th>Ruta</th><th>Detalle</th></tr></thead><tbody>$resRows</tbody></table>
        <p class="text-muted" style="font-size:11px; margin-top:6px;">Si hay entradas aqui, Excel ya intento protegerse solo. Considera re-habilitar tras actualizar el Add-in o dejar deshabilitado.</p>
    </div>

    <div class="card">
        <h3>4. Aceleracion Grafica</h3>
        <table><tbody><tr><td>Estado</td><td><span class="badge $gfxBadge">$gfxStatusEsc</span></td><td class="text-muted">Registro: $(ConvertTo-HtmlEscaped $gfx.PathRegistry)</td></tr><tr><td>DisableHardwareAcceleration</td><td>$gfxValEsc</td><td>GPO: $gfxGpoEsc</td></tr></tbody></table>
        <p class="text-muted" style="font-size:11px; margin-top:6px;">Deshabilitar aceleracion suele corregir cuelgues al copiar rangos grandes o con formato condicional/graficos.</p>
    </div>

    <div class="card $(if($xlFiles.Count -gt 0 -and ($xlFiles | Where-Object {\$_.Suspicious})){'card-bad'}else{''})">
        <h3>5. Archivos XLSTART / STARTUP (carga automatica)</h3>
        <table><thead><tr><th>Archivo</th><th>Tamano</th><th>Modificado</th><th>Directorio</th><th>Estado</th></tr></thead><tbody>$xlRows</tbody></table>
    </div>

    <div class="card $(if($hookBad -gt 0){'card-bad'}else{'card-ok'})">
        <h3>6. Procesos en ejecucion</h3>
        <table><thead><tr><th>Proceso</th><th>PID</th><th>Ruta</th><th>Estado</th></tr></thead><tbody>$hookRows</tbody></table>
        <p class="text-muted" style="font-size:11px; margin-top:6px;">Lista de procesos comunes. Si alguno aparece, prueba cerrarlo y repite la copia en Excel.</p>
    </div>

    <div class="card $clipCardClass">
        <h3>7. Portapapeles</h3>
        <table><tbody>
            <tr><td>Disponibilidad</td><td><span class="badge $clipBadge">$clipOpenEsc</span></td><td>Si es "bloqueado", otro proceso tiene el portapapeles abierto</td></tr>
            <tr><td>SequenceNumber</td><td>$clipSeqEsc</td><td class="text-muted">Incrementa en cada actualizacion</td></tr>
            <tr><td>Owner actual</td><td>$clipOwnerEsc</td><td>PID</td></tr>
            <tr><td>Preview (texto)</td><td style="word-break:break-all;">$clipPrevEsc</td><td class="text-muted">Primeros 80 chars</td></tr>
            <tr><td>Formatos</td><td>$clipFmtEsc</td><td class="text-muted">Estado Historial (HKCU\Clipboard)</td></tr>
        </tbody></table>
        $(if($clipErrEsc){"<p class='text-muted' style='font-size:11px; margin-top:6px;'>Error: $clipErrEsc</p>"})
        <div class="rec-box">Sugerencia: usa Monitor-Portapapeles.ps1 para ver cambios en tiempo real.</div>
    </div>

    <div class="card">
        <h3>8. Registro Relevante Excel / ProtectedView</h3>
        <table><thead><tr><th>Ruta</th><th>Nombre</th><th>Valor</th><th>Descripcion</th></tr></thead><tbody>$regRows</tbody></table>
    </div>

    <div class="card">
        <h3>9. Procesos Excel en Ejecucion</h3>
        <table><thead><tr><th>PID</th><th>CPU (s)</th><th>RAM</th><th>Handles</th><th>Estado</th></tr></thead><tbody>$excelRows</tbody></table>
        <p class="text-muted" style="font-size:11px; margin-top:6px;">Handles &gt; 5000 o RAM &gt; 1.5GB con Excel colgado sugiere fuga / add-in.</p>
    </div>

    <div class="card $(if($hangs.Count -gt 0){'card-bad'}else{''})">
        <h3>10. Eventos de Cuelgue/Crash Excel (Application Log, IDs 1000/1001/1002, ultimos $Days dias)</h3>
        <table><thead><tr><th>Fecha</th><th>Origen</th><th>ID</th><th>Tipo</th><th>Resumen</th></tr></thead><tbody>$hangRows</tbody></table>
    </div>

    <div class="card">
        <h3>11. Reinicio Pendiente</h3>
        <table><tbody>$pendingRows</tbody></table>
        <p class="text-muted" style="font-size:11px; margin-top:6px;">Un reinicio pendiente puede dejar el portapapeles inestable tras update de Office.</p>
    </div>

    <div class="card">
        <h3>12. Acciones Recomendadas (paso a paso para tu caso)</h3>
        <ol style="margin-left:18px; font-size:13px;">
            <li>Cierra interceptores listados en seccion 6. Si dudas, cierra todo: <code>PowerToys, Ditto, ClipClip, ShareX, Grammarly, DeepL, KeePass</code> y reintenta copiar.</li>
            <li>Prueba <code>excel /safe</code>. Si funciona, ve a Archivo &gt; Opciones &gt; Complementos &gt; COM &gt; Ir &gt; desmarca Add-ins con LoadBehavior 3 uno a uno.</li>
            <li>Si estas por RDP: en el equipo remoto ejecuta <code>taskkill /f /im rdpclip.exe; Start-Process rdpclip.exe</code></li>
            <li>Deshabilita aceleracion grafica si hay cuelgues al copiar rangos con formato/graficos.</li>
            <li>Revisa <code>%APPDATA%\Microsoft\Excel\XLSTART</code> - renombra PERSONAL.XLSB temporalmente y prueba.</li>
            <li>Lanza <code>.\Monitor-Portapapeles.ps1 -IntervalMs 300</code> en otra consola, copia en Excel y observa si el contenido cambia en &lt;1s a otro texto/vacio.</li>
            <li>Si persiste: repara Office ClickToRun: Configuracion &gt; Aplicaciones &gt; Microsoft 365 &gt; Modificar &gt; Reparacion rapida (y luego en linea si no resuelve).</li>
        </ol>
    </div>

    <div class="footer">
        Reporte generado automaticamente | Auditoria-Office-Clipboard.ps1 | $ReportDate | Host: $computerEsc<br>
        Uso: <code>.\Auditoria-Office-Clipboard.ps1</code> (HTML) | <code>Invoke-OfficeAudit -AsJson | Out-File office_audit.json -Encoding utf8</code> (JSON) | <code>. .\Auditoria-Office-Clipboard.ps1; Get-ExcelComAddins</code> (modulo)
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
Write-Host " Reporte generado con exito en:" -ForegroundColor Green
Write-Host " $OutputFile" -ForegroundColor Cyan
if ($oneDriveWarn) { Write-Host " ADVERTENCIA: Destino en OneDrive - datos en nube" -ForegroundColor Yellow }
try {
    $hash = (Get-FileHash -Path $OutputFile -Algorithm SHA256 -ErrorAction Stop).Hash
    Write-Host " SHA256: $hash" -ForegroundColor Gray
    Add-Content -Path $OutputFile -Value "<!-- SHA256:$hash UTC:$((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'))Z -->" -ErrorAction SilentlyContinue
} catch {}
Write-Host "==================================================" -ForegroundColor Green
if (-not $NoOpen) { try { Start-Process $OutputFile -ErrorAction Stop } catch { Write-Host "Abre manualmente: $OutputFile" -ForegroundColor Yellow } } else { Write-Host " NoOpen: reporte no abierto automaticamente." -ForegroundColor Gray }
# Exit code para RMM: 0=ok, 1=hallazgos
$exitBad = 0
if ($hookBad -gt 0 -or $clipBadge -eq "bad" -or $hangs.Count -gt 0) { $exitBad = 1 }
if ($exitBad -gt 0) { exit 1 } else { exit 0 }
