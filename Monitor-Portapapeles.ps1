<#
.SYNOPSIS
    Monitor en tiempo real del portapapeles - registra cambios.
.DESCRIPTION
    Para diagnostico de Excel "copio varias celdas y no se pegan en filas inferiores"
    este script vigila el portapapeles en bucle y registra cada cambio con timestamp,
    PID/proceso dueno, formatos, hash y preview del contenido. Indica cuando el
    contenido cambia en <1.5s por un proceso distinto.

    No instala nada, no requiere Admin. Usa Win32 API (user32.dll) y Get-Clipboard.
    Compatible PowerShell 5.1+ (STA recomendado).

    Relacionado: Auditoria-Office-Clipboard.ps1 hace captura estatica;
    este script hace prueba dinamica en vivo.

.PARAMETER IntervalMs
    Intervalo de sondeo en ms (default 300). Menor = mas preciso pero mas CPU.

.PARAMETER DurationSec
    Duracion total en segundos. 0 = infinito hasta Ctrl+C (default 0).

.PARAMETER LogPath
    Ruta opcional a CSV para guardar historial (ej. C:\diag\clip_log.csv).

.PARAMETER MaxPreviewChars
    Max caracteres del preview mostrado (default 120).

.PARAMETER IncludeImageHash
    Si se especifica, tambien hashea imagen del clipboard (mas lento).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Monitor-Portapapeles.ps1
    # Deja corriendo, luego copia en Excel. Observa Owner y cambios <1s.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Monitor-Portapapeles.ps1 -IntervalMs 200 -DurationSec 60 -LogPath C:\diag\clip.csv

.NOTES
    PowerShell ISE y VS Code corren en STA por defecto; si ves aviso MTA, relanza con:
    powershell -STA -ExecutionPolicy Bypass -File .\Monitor-Portapapeles.ps1
    Requiere Windows 10/11. Get-ClipboardOwner funciona aunque otro proceso no libere clipboard.
#>

#Requires -Version 5.1

param(
    [int]$IntervalMs = 300,
    [int]$DurationSec = 0,
    [string]$LogPath = "",
    [int]$MaxPreviewChars = 120,
    [switch]$IncludeImageHash
)

$ErrorActionPreference = "SilentlyContinue"

# Aviso STA/MTA: Get-Clipboard y COM requieren STA para fiabilidad
try {
    $apt = [System.Threading.Thread]::CurrentThread.GetApartmentState()
    if ($apt -ne "STA") {
        Write-Host "AVISO: Hilo actual es $apt, no STA. Get-Clipboard puede fallar o dar lecturas stale." -ForegroundColor Yellow
        Write-Host "Relanza con: powershell -STA -ExecutionPolicy Bypass -File `"$PSCommandPath`" -IntervalMs $IntervalMs" -ForegroundColor DarkYellow
    }
} catch {}

# Cargar Win32 API una sola vez
try {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public class ClipMon {
    [DllImport("user32.dll")] public static extern uint GetClipboardSequenceNumber();
    [DllImport("user32.dll")] public static extern IntPtr GetClipboardOwner();
    [DllImport("user32.dll")] public static extern bool OpenClipboard(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool CloseClipboard();
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    [DllImport("user32.dll")] public static extern int CountClipboardFormats();
    [DllImport("user32.dll")] public static extern uint EnumClipboardFormats(uint format);
    [DllImport("user32.dll")] public static extern int GetClipboardFormatName(uint format, System.Text.StringBuilder lpszFormatName, int cchMaxCount);
}
"@ -ErrorAction Stop
} catch {}

function Get-ClipboardOwnerProcess {
    try {
        $owner = [ClipMon]::GetClipboardOwner()
        if ($owner -eq [IntPtr]::Zero) { return @{ PID=0; Name="(sin owner / clipboard libre)"; Handle=$owner } }
        $pidOut = [uint32]0
        [void][ClipMon]::GetWindowThreadProcessId($owner, [ref]$pidOut)
        $name = "(PID $pidOut)"
        try { $p = Get-Process -Id $pidOut -ErrorAction Stop; $name = $p.ProcessName } catch {}
        return @{ PID=$pidOut; Name=$name; Handle=$owner }
    } catch {
        return @{ PID=-1; Name="Error: $($_.Exception.Message)"; Handle=[IntPtr]::Zero }
    }
}

function Get-ClipboardPreview {
    param([int]$MaxChars=120)
    $preview = ""
    $hash = ""
    $format = "Texto"
    try {
        # Intentar texto primero
        $txt = Get-Clipboard -ErrorAction SilentlyContinue
        if ($null -ne $txt -and "$txt" -ne "") {
            $s = "$txt"
            # Normalizar saltos de linea para preview
            $sOneLine = ($s -replace "`r`n"," | " -replace "`n"," | " -replace "`r"," | ")
            if ($sOneLine.Length -gt $MaxChars) { $preview = $sOneLine.Substring(0,$MaxChars) + "..." }
            else { $preview = $sOneLine }
            # Hash para detectar cambios aunque preview truncado
            try { $bytes = [System.Text.Encoding]::UTF8.GetBytes($s); $h = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new($bytes)) -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash; $hash = $h.Substring(0,12) } catch { $hash = "nohash" }
            # Info extra: si es TSV (rangos Excel suelen ser tab-separated)
            $lines = ($s -split "`r?`n").Count
            $tabs = ($s -split "`t").Count - 1
            if ($tabs -gt 0) { $format = "Texto TSV ($lines filas, $tabs tabs)" }
            elseif ($lines -gt 1) { $format = "Texto multilinea ($lines lineas)" }
            else { $format = "Texto ($($s.Length) chars)" }
        } else {
            # Probar imagen
            try {
                $img = Get-Clipboard -Format Image -ErrorAction SilentlyContinue
                if ($img) {
                    $preview = "[Imagen $([math]::Round($img.Width))x$([math]::Round($img.Height))]"
                    $format = "Imagen"
                    if ($IncludeImageHash) {
                        try { $ms = New-Object System.IO.MemoryStream; $img.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png); $ms.Position=0; $hash=(Get-FileHash -InputStream $ms -Algorithm SHA256).Hash.Substring(0,12) } catch { $hash="img-nohash" }
                    } else { $hash = "img" }
                } else {
                    $preview = "(vacio)"
                    $format = "Vacio"
                    $hash = "empty"
                }
            } catch {
                $preview = "(vacio o formato no texto)"
                $format = "Desconocido"
                $hash = "unknown"
            }
        }
    } catch {
        $preview = "Error: $($_.Exception.Message)"
        $format = "Error"
        $hash = "err"
    }
    # Contar formatos disponibles via API (si falla, dejar formato textual)
    try {
        $cnt = [ClipMon]::CountClipboardFormats()
        if ($cnt -gt 0) { $format += " | $cnt formatos" }
    } catch {}
    return @{ Preview=$preview; Hash=$hash; Format=$format }
}

function Get-ClipboardChangeFlag {
    param($PrevEntry, $CurrEntry, $DeltaMs)
    # Marca si: cambio en <1500ms, owner distinto, y contenido se vacia
    if (-not $PrevEntry) { return $false }
    if ($DeltaMs -gt 1500) { return $false }
    if ($CurrEntry.OwnerPID -eq $PrevEntry.OwnerPID -and $CurrEntry.OwnerPID -ne 0) { return $false }
    # Si el nuevo contenido es vacio
    if ($CurrEntry.Format -like "Vacio*") { return $true }
    if ($CurrEntry.Preview -eq "(vacio)") { return $true }
    # Cambio de owner en <1.5s si previo era Excel
    if ($PrevEntry.OwnerName -like "*EXCEL*" -and $CurrEntry.OwnerName -notlike "*EXCEL*") { return $true }
    return $false
}

# Preparar log CSV si se pide
$logFile = $null
if ($LogPath) {
    try {
        $dir = Split-Path $LogPath -Parent
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        # Cabecera
        "Timestamp,SeqNumber,OwnerPID,OwnerName,Format,Hash,Preview,DeltaMs,ChangeFlag" | Out-File -FilePath $LogPath -Encoding utf8 -Force
        $logFile = $LogPath
        Write-Host "Log CSV: $LogPath" -ForegroundColor Gray
    } catch { Write-Host "No se pudo crear log ${LogPath}: $($_.Exception.Message)" -ForegroundColor Yellow }
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " Monitor de Portapapeles - Tiempo Real" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " Intervalo: ${IntervalMs}ms | Duracion: $(if($DurationSec -eq 0){'infinito (Ctrl+C para salir)'}else{"${DurationSec}s"}) | MaxPreview: $MaxPreviewChars chars" -ForegroundColor Gray
Write-Host " Instrucciones: deja este script corriendo y copia VARIAS celdas en Excel (Ctrl+C)." -ForegroundColor Yellow
Write-Host " Si otro programa modifica el portapapeles veras aqui un cambio con Owner distinto en <1.5s marcado ALERTA." -ForegroundColor Yellow
Write-Host "--------------------------------------------------" -ForegroundColor DarkGray
Write-Host ("{0,-12} {1,-8} {2,-18} {3,-22} {4}" -f "Hora", "Seq", "Owner", "Formato", "Preview (hash)") -ForegroundColor DarkGray
Write-Host "--------------------------------------------------" -ForegroundColor DarkGray

$startTime = Get-Date
$lastSeq = 0
try { $lastSeq = [ClipMon]::GetClipboardSequenceNumber() } catch { $lastSeq = 0 }
$lastEntry = $null
$lastChangeTime = Get-Date
$counter = 0
$alertCount = 0

# Mostrar estado inicial
try {
    $owner0 = Get-ClipboardOwnerProcess
    $prev0 = Get-ClipboardPreview -MaxChars $MaxPreviewChars
    $ts0 = Get-Date -Format "HH:mm:ss.fff"
    Write-Host ("{0,-12} {1,-8} {2,-18} {3,-22} {4}" -f $ts0, $lastSeq, "$($owner0.Name)($($owner0.PID))", $prev0.Format, "$($prev0.Preview) [$($prev0.Hash)]") -ForegroundColor DarkGray
    $lastEntry = @{ OwnerPID=$owner0.PID; OwnerName=$owner0.Name; Format=$prev0.Format; Preview=$prev0.Preview; Hash=$prev0.Hash; Seq=$lastSeq }
} catch {}

# Bucle principal
try {
    while ($true) {
        Start-Sleep -Milliseconds $IntervalMs
        $counter++

        # Control duracion
        if ($DurationSec -gt 0 -and ((Get-Date) - $startTime).TotalSeconds -ge $DurationSec) {
            Write-Host "`nDuracion alcanzada ($DurationSec s). Saliendo." -ForegroundColor Cyan
            break
        }

        $currSeq = 0
        try { $currSeq = [ClipMon]::GetClipboardSequenceNumber() } catch { continue }

        if ($currSeq -ne $lastSeq) {
            $now = Get-Date
            $deltaMs = [math]::Round((($now - $lastChangeTime).TotalMilliseconds),0)
            $owner = Get-ClipboardOwnerProcess
            $clip = Get-ClipboardPreview -MaxChars $MaxPreviewChars
            $ts = $now.ToString("HH:mm:ss.fff")

            $isSuspicious = Get-ClipboardChangeFlag -PrevEntry $lastEntry -CurrEntry @{ OwnerPID=$owner.PID; OwnerName=$owner.Name; Format=$clip.Format; Preview=$clip.Preview } -DeltaMs $deltaMs

            $color = "Green"
            $flag = ""
            if ($isSuspicious) {
                $color = "Red"
                $flag = " <<< ALERTA: cambio rapido de portapapeles! ($deltaMs ms, $($lastEntry.OwnerName)->$($owner.Name))"
                $alertCount++
                [Console]::Beep(1200, 250)
            } elseif ($deltaMs -lt 800) {
                $color = "Yellow"
                $flag = " ($deltaMs ms)"
            } else {
                $color = "White"
            }

            $ownerStr = "$($owner.Name)($($owner.PID))"
            if ($ownerStr.Length -gt 18) { $ownerStr = $ownerStr.Substring(0,18) }
            $fmtStr = $clip.Format
            if ($fmtStr.Length -gt 22) { $fmtStr = $fmtStr.Substring(0,22) }
            $prevStr = "$($clip.Preview) [$($clip.Hash)]$flag"

            Write-Host ("{0,-12} {1,-8} {2,-18} {3,-22} {4}" -f $ts, $currSeq, $ownerStr, $fmtStr, $prevStr) -ForegroundColor $color

            # Log CSV
            if ($logFile) {
                try {
                    $escPreview = $clip.Preview -replace '"','""'
                    $escFormat = $clip.Format -replace '"','""'
                    $escOwner = $owner.Name -replace '"','""'
                    $line = '"{0}","{1}","{2}","{3}","{4}","{5}","{6}","{7}","{8}"' -f $ts, $currSeq, $owner.PID, $escOwner, $escFormat, $clip.Hash, $escPreview, $deltaMs, $isSuspicious
                    $line | Out-File -FilePath $logFile -Encoding utf8 -Append
                } catch {}
            }

            # Actualizar estado
            $lastSeq = $currSeq
            $lastChangeTime = $now
            $lastEntry = @{ OwnerPID=$owner.PID; OwnerName=$owner.Name; Format=$clip.Format; Preview=$clip.Preview; Hash=$clip.Hash; Seq=$currSeq }

            # Consejo especifico si Excel pierde ownership rapido
            if ($isSuspicious) {
                Write-Host "  -> Consejo: cierra el proceso '$($owner.Name)' y repite la copia en Excel. Si el problema desaparece, ese era el culpable." -ForegroundColor Yellow
                Write-Host "     Tambien prueba: rdpclip reinicio (si RDP), deshabilitar Clipboard History, o cerrar PowerToys/Ditto/ShareX/Grammarly." -ForegroundColor Yellow
            }
        }

        # Feedback cada 60 iteraciones si no hay cambios (latido)
        if ($counter % 200 -eq 0) {
            # No spamear, solo punto
            Write-Host "." -NoNewline -ForegroundColor DarkGray
            if ($counter % 2000 -eq 0) { Write-Host "" }
        }
    }
} catch [System.Management.Automation.PipelineStoppedException] {
    Write-Host "`nInterrumpido por usuario (Ctrl+C)." -ForegroundColor Cyan
} finally {
    Write-Host "`n==================================================" -ForegroundColor Cyan
    Write-Host " Resumen: $alertCount alerta(s) de cambio rapido detectadas." -ForegroundColor $(if($alertCount -gt 0){"Red"}else{"Green"})
    if ($alertCount -eq 0) {
        Write-Host " Si copiaste en Excel y no hubo alerta, el portapapeles NO fue sobreescrito por otro proceso." -ForegroundColor Green
        Write-Host " Entonces el problema es interno de Excel: Add-in, XLSTART o aceleracion grafica (ver Auditoria-Office-Clipboard.html)." -ForegroundColor Gray
    } else {
        Write-Host " Hay evidencia de que otro proceso sobreescribe el portapapeles tras la copia." -ForegroundColor Yellow
        Write-Host " Revisa el Owner de cada ALERTA arriba para identificar el culpable." -ForegroundColor Yellow
    }
    if ($logFile) { Write-Host " Log guardado en: $logFile" -ForegroundColor Cyan }
    Write-Host "==================================================" -ForegroundColor Cyan
}
