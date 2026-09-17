<#
.SYNOPSIS
    Auditoria Office/Excel - Reporte HTML de configuracion y diagnostico.
.DESCRIPTION
    Recopila informacion de configuracion de Microsoft Office y Excel: version
    ClickToRun, COM Add-ins, resiliency, aceleracion grafica, archivos XLSTART,
    procesos relacionados con portapapeles, procesos Excel en ejecucion, eventos
    de hang y reinicio pendiente. Genera reporte HTML portable.

    El acceso al portapapeles solo se realiza si se especifica -IncludeClipboardCheck.
    Sin ese parametro, solo se consulta el estado del historial de portapapeles
    via registro (HKCU\Software\Microsoft\Clipboard).

    Mantiene 9 bloques: Office ClickToRun, COM Addins LB, Resiliency,
    Gfx DisableHardwareAcceleration, XLSTART/STARTUP, procesos relacionados,
    procesos Excel, eventos Hang 1000/1002 (5 max), reinicio pendiente.

    Para diagnostico detallado de portapapeles con lectura de contenido, usa:
      .\Auditoria-Office-Clipboard-Light.ps1 -IncludeClipboardCheck
    o la version completa Auditoria-Office-Clipboard.ps1.

    Proposito: soporte IT interno - diagnostico de Excel portapapeles.
    Author: WindowsDiagnosis - Xeland IT Support
    License: MIT

.NOTES
    Compatible PowerShell 5.1+ sin Admin (HKCU). ASCII puro. HTML portable.
    Uso: powershell -ExecutionPolicy Bypass -File .\Auditoria-Office-Clipboard-Light.ps1
#>

#Requires -Version 5.1

param(
    [string]$OutputPath = "",
    [switch]$NoOpen,
    [int]$Days = 7,
    [switch]$IncludeClipboardCheck,
    [switch]$AsJson,
    [string]$JsonPath = ""
)

if ($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage") {
    Write-Host "ADVERTENCIA: LanguageMode=$($ExecutionContext.SessionState.LanguageMode)" -ForegroundColor Yellow
}
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    $sysNative = "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe"
    $target = if (Test-Path $sysNative) { $sysNative } else { "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" }
    Write-Host "AVISO: 32-bit en OS 64-bit. Relanzando en 64-bit..." -ForegroundColor Yellow
    try { & $target -ExecutionPolicy Bypass -File $PSCommandPath @PSBoundParameters; exit $LASTEXITCODE } catch { Write-Host "No se pudo relanzar: $($_.Exception.Message)" -ForegroundColor Yellow }
}

$ErrorActionPreference = "SilentlyContinue"

function ConvertTo-HtmlEscaped { param([string]$Text) if($null -eq $Text){return ""} return [System.Net.WebUtility]::HtmlEncode($Text) }
function Get-DesktopPathSafe {
    $desktop=[Environment]::GetFolderPath("Desktop"); if(-not $desktop -or -not (Test-Path $desktop)){$desktop="$env:USERPROFILE\Desktop"}
    $isOneDrive=($desktop -like "*OneDrive*"); return @{Path=$desktop; IsOneDrive=$isOneDrive}
}
function Test-PendingReboot {
    $r=@()
    if(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"){$r+="CBS RebootPending"}
    if(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"){$r+="WU RebootRequired"}
    try{if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction Stop).PendingFileRenameOperations){$r+="PendingFileRenameOperations"}}catch{}
    return $r
}

function Get-OfficeInfo {
    $info=[PSCustomObject]@{ ProductReleaseIds="N/D"; VersionToReport="N/D"; ClientCulture="N/D"; UpdateChannel="N/D"; OfficeApps=@() }
    try{
        $c2r="HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
        if(Test-Path $c2r){
            $p=Get-ItemProperty -Path $c2r -ErrorAction Stop
            $info.ProductReleaseIds=$p.ProductReleaseIds; $info.VersionToReport=$p.VersionToReport; $info.ClientCulture=$p.ClientCulture
            $url="$($p.CDNBaseUrl)"
            if($url -match "492350f6-3a01-4f97-b9c0-c7c6ddf67d60"){$info.UpdateChannel="Current Channel"}
            elseif($url -match "64256afe-f5d9-4f86-8936-8840a6a4f5be"){$info.UpdateChannel="Monthly Enterprise"}
            elseif($url -match "55336b82-a18d-4dd6-b5f6-9e5095c314a6"){$info.UpdateChannel="Semi-Annual"}
            else{$info.UpdateChannel=$url}
        }
        $root="${env:ProgramFiles}\Microsoft Office\root\Office16"
        if(Test-Path $root){
            foreach($exe in @("EXCEL.EXE","WINWORD.EXE")){
                $fp=Join-Path $root $exe; if(Test-Path $fp){ try{$vi=(Get-Item $fp).VersionInfo.FileVersion}catch{$vi="N/D"}; $info.OfficeApps+=[PSCustomObject]@{App=$exe; Version=$vi; Path=$fp} }
            }
        }
    } catch {}
    return $info
}

function Get-ExcelComAddins {
    $paths=@("HKCU:\Software\Microsoft\Office\Excel\Addins","HKLM:\SOFTWARE\Microsoft\Office\Excel\Addins","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Excel\Addins")
    $res=@()
    foreach($path in $paths){
        if(Test-Path $path){
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                $props=Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                $lb=$props.LoadBehavior
                $status=switch($lb){ 3{"Activo (Carga al Inicio)"} 2{"Desactivado"} 0{"Desconectado"} default{"Desconocido ($lb)"} }
                $badge=if($lb -eq 3){"warn"}else{"ok"}
                $res+=[PSCustomObject]@{ AddInName=$_.PSChildName; Status=$status; Badge=$badge; LoadBehavior=$lb; Description=$props.FriendlyName; RegistryPath=$path }
            }
        }
    }
    return $res
}

function Get-ExcelResiliency {
    $rows=@()
    $base="HKCU:\Software\Microsoft\Office\16.0\Excel\Resiliency\DisabledItems"
    if(Test-Path $base){
        try{
            $props=Get-ItemProperty -Path $base -ErrorAction SilentlyContinue
            foreach($p in $props.PSObject.Properties){ if($p.Name -match "^PS"){continue}
                $rows+=[PSCustomObject]@{Area="DisabledItems"; Name=$p.Name; Path=$base; Detail="Add-in deshabilitado tras cuelgue"}
            }
        } catch {}
        try{
            $items=Get-ChildItem -Path $base -ErrorAction SilentlyContinue
            foreach($it in $items){ $rows+=[PSCustomObject]@{Area="DisabledItems"; Name=$it.PSChildName; Path=$base; Detail="Entrada resiliency"} }
        } catch {}
    }
    return $rows
}

function Get-OfficeGfxStatus {
    $path="HKCU:\Software\Microsoft\Office\16.0\Common\Graphics"
    $raw=$null; $status="Habilitada (Por defecto)"; $badge="ok"
    if(Test-Path $path){ $raw=(Get-ItemProperty -Path $path -Name DisableHardwareAcceleration -ErrorAction SilentlyContinue).DisableHardwareAcceleration; if($raw -eq 1){$status="Deshabilitada"; $badge="warn"} }
    return [PSCustomObject]@{AceleracionGrafica=$status; Valor=$raw; PathRegistry=$path; Badge=$badge}
}

function Get-XLSTARTFiles {
    $paths=@("$env:APPDATA\Microsoft\Excel\XLSTART","$env:APPDATA\Microsoft\Word\STARTUP")
    $files=@()
    foreach($path in $paths){
        if(Test-Path $path){
            try{
                Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | ForEach-Object {
                    $files+=[PSCustomObject]@{ FileName=$_.Name; SizeKB=[math]::Round($_.Length/1KB,2); LastWriteTime=$_.LastWriteTime; Directory=$_.DirectoryName; ReviewFlag=($_.Extension -match "\.(xlam|xla|dotm)")}
                }
            } catch {}
        }
    }
    return $files
}

# Lista de procesos comunes relacionados con portapapeles
function Get-ClipboardHooksLight {
    $known=@("PowerToys","Ditto","ShareX","Greenshot","Grammarly","DeepL","RazerSynapse","RdpClip")
    $found=@()
    try{
        Get-Process -ErrorAction SilentlyContinue | Where-Object { $known -contains $_.ProcessName } | ForEach-Object {
            $st="N/D"; try{$st=$_.StartTime}catch{}
            $found+=[PSCustomObject]@{ ProcessName=$_.ProcessName; PID=$_.Id; Path=$_.Path; StartTime=$st }
        }
    } catch {}
    return $found
}

# LIGHT: sin P/Invoke, solo registro + Get-Clipboard opt-in
function Get-ClipboardHealthLight {
    param([switch]$IncludeCheck)
    $result=[PSCustomObject]@{ CanOpen="No evaluado (modo LIGHT)"; Historial="N/D"; Preview="(no leido - modo no invasivo)"; Badge="ok"; Nota="Use -IncludeClipboardCheck para leer Get-Clipboard (sigue sin P/Invoke)" }
    try{
        $hist=(Get-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -ErrorAction SilentlyContinue).EnableClipboardHistory
        if($hist -eq 1){$result.Historial="Activado (puede interferir TSV)"}
        elseif($hist -eq 0){$result.Historial="Desactivado"}
        else{$result.Historial="No configurado"}
    } catch {}
    if($IncludeCheck){
        try{
            $txt=Get-Clipboard -ErrorAction Stop
            if($null -ne $txt -and "$txt" -ne ""){
                $s="$txt"; if($s.Length -gt 40){$s=$s.Substring(0,40)+"..."}
                $result.Preview=$s -replace "`r`n"," | "
                $result.CanOpen="Get-Clipboard OK"
                $result.Nota="Contenido leido bajo consentimiento -IncludeClipboardCheck"
            } else { $result.Preview="(vacio)"; $result.CanOpen="Get-Clipboard vacio" }
        } catch { $result.Preview="Error Get-Clipboard: $($_.Exception.Message)"; $result.Badge="warn" }
    }
    return $result
}

function Get-ExcelRunningLight {
    $procs=@()
    try{
        $procs=Get-Process -Name EXCEL -ErrorAction SilentlyContinue | ForEach-Object {
            $st="N/D"; try{$st=$_.StartTime}catch{}
            [PSCustomObject]@{ PID=$_.Id; RAM_MB=[math]::Round($_.WorkingSet/1MB,1); Handles=$_.HandleCount; StartTime=$st; Responding=$_.Responding }
        }
    } catch {}
    return $procs
}

function Get-HangLight {
    param([int]$Days=7)
    $ev=@()
    try{
        $ev=Get-WinEvent -FilterHashtable @{LogName='Application'; ID=1000,1002; StartTime=(Get-Date).AddDays(-$Days)} -ErrorAction Stop |
            Where-Object { $_.Message -like "*excel.exe*"} | Select-Object -First 5 |
            ForEach-Object { [PSCustomObject]@{ TimeCreated=$_.TimeCreated; EventID=$_.Id; Provider=$_.ProviderName; Summary=(($_.Message -split "`r?`n")[0]) } }
    } catch {}
    return $ev
}

# --- Recoleccion ---
$ReportDate=Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ComputerName=$env:COMPUTERNAME
$desktopInfo=Get-DesktopPathSafe
$desktopPath=$desktopInfo.Path
$oneDriveWarn=$desktopInfo.IsOneDrive

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " Auditoria Office - $ComputerName" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
if(-not $IncludeClipboardCheck){ Write-Host " Portapapeles no leido por defecto. Usa -IncludeClipboardCheck para lectura." -ForegroundColor DarkGray }

$officeInfo=Get-OfficeInfo
$addins=Get-ExcelComAddins
$resiliency=Get-ExcelResiliency
$gfx=Get-OfficeGfxStatus
$xlFiles=Get-XLSTARTFiles
$hooks=Get-ClipboardHooksLight
$clip=Get-ClipboardHealthLight -IncludeCheck:$IncludeClipboardCheck
$excelProcs=Get-ExcelRunningLight
$hangs=Get-HangLight -Days $Days
$pending=Test-PendingReboot

# AsJson (sin P/Invoke)
if($AsJson){
    $report=[PSCustomObject]@{ AuditTimestamp=$ReportDate; HostName=$ComputerName; Mode="LIGHT"; OfficeInfo=$officeInfo; HardwareAcceleration=$gfx; ComAddins=$addins; Resiliency=$resiliency; XLSTARTFiles=$xlFiles; HookProcesses=$hooks; ClipboardHealth=$clip; ExcelProcesses=$excelProcs; RecentExcelHangLogs=$hangs; PendingReboot=$pending }
    $json=$report | ConvertTo-Json -Depth 5
    if($JsonPath){ $json | Out-File -FilePath $JsonPath -Encoding utf8 -Force; Write-Host "JSON -> $JsonPath" -ForegroundColor Green } else { Write-Output $json }
    return
}

# --- HTML ---
$pendingRows=if($pending.Count -gt 0){"<tr class='row-bad'><td>Reboot pendiente</td><td>$(ConvertTo-HtmlEscaped ($pending -join ', '))</td><td><span class='badge bad'>Reinicio requerido</span></td></tr>"}else{"<tr><td>Reboot pendiente</td><td>Ninguno</td><td><span class='badge ok'>OK</span></td></tr>"}

$officeRows=""
if($officeInfo.OfficeApps.Count -gt 0){ foreach($a in $officeInfo.OfficeApps){ $officeRows+="<tr><td>$(ConvertTo-HtmlEscaped $a.App)</td><td>$(ConvertTo-HtmlEscaped $a.Version)</td><td style='word-break:break-all;'>$(ConvertTo-HtmlEscaped $a.Path)</td></tr>" }
} else { $officeRows="<tr><td colspan='3' class='text-muted'>No se detecto Office ClickToRun (posible MSI/Store).</td></tr>" }

$addinRows=""
if($addins.Count -gt 0){ foreach($ad in $addins){ $cls=if($ad.Badge -eq "warn"){"row-bad"}else{""}; $addinRows+="<tr class='$cls'><td>$(ConvertTo-HtmlEscaped $ad.AddInName)</td><td><span class='badge $($ad.Badge)'>$(ConvertTo-HtmlEscaped $ad.Status)</span></td><td>$($ad.LoadBehavior)</td><td>$(ConvertTo-HtmlEscaped $ad.RegistryPath)</td></tr>" }
} else { $addinRows="<tr><td colspan='4' class='text-ok'>Sin COM Add-ins (limpio).</td></tr>" }

$resRows=if($resiliency.Count -gt 0){ ($resiliency | ForEach-Object { "<tr class='row-bad'><td>$(ConvertTo-HtmlEscaped $_.Area)</td><td>$(ConvertTo-HtmlEscaped $_.Name)</td><td>$(ConvertTo-HtmlEscaped $_.Detail)</td></tr>" }) -join "" } else { "<tr><td colspan='3' class='text-ok'>Sin DisabledItems (no cuelgues recientes).</td></tr>" }

$xlRows=if($xlFiles.Count -gt 0){ ($xlFiles | ForEach-Object { $badge=if($_.ReviewFlag){"<span class='badge bad'>Revisar</span>"}else{"<span class='badge ok'>OK</span>"}; "<tr><td>$(ConvertTo-HtmlEscaped $_.FileName)</td><td>$($_.SizeKB) KB</td><td>$($_.LastWriteTime.ToString('yyyy-MM-dd'))</td><td>$badge</td></tr>" }) -join "" } else { "<tr><td colspan='4' class='text-ok'>XLSTART vacio.</td></tr>" }

$hookRows=if($hooks.Count -gt 0){ ($hooks | ForEach-Object { "<tr class='row-bad'><td><strong>$(ConvertTo-HtmlEscaped $_.ProcessName)</strong></td><td>$($_.PID)</td><td><span class='badge bad'>Posible interceptor</span></td></tr>" }) -join "" } else { "<tr><td colspan='3' class='text-ok'>Ningun interceptor de lista corta (8) en ejecucion.</td></tr>" }

$clipBadge=$clip.Badge
$clipHistEsc=ConvertTo-HtmlEscaped $clip.Historial
$clipPrevEsc=ConvertTo-HtmlEscaped $clip.Preview
$clipNotaEsc=ConvertTo-HtmlEscaped $clip.Nota

$excelRows=if($excelProcs.Count -gt 0){ ($excelProcs | ForEach-Object { $b=if($_.Responding){"ok"}else{"bad"}; $t=if($_.Responding){"Responde"}else{"No responde"}; "<tr><td>$($_.PID)</td><td>$($_.RAM_MB) MB</td><td>$($_.Handles)</td><td><span class='badge $b'>$t</span></td></tr>" }) -join "" } else { "<tr><td colspan='4' class='text-muted'>Excel no en ejecucion.</td></tr>" }

$hangRows=if($hangs.Count -gt 0){ ($hangs | ForEach-Object { "<tr class='row-bad'><td>$($_.TimeCreated.ToString('MM-dd HH:mm'))</td><td>$(ConvertTo-HtmlEscaped $_.Provider)</td><td>$($_.EventID)</td><td>$(ConvertTo-HtmlEscaped $_.Summary)</td></tr>" }) -join "" } else { "<tr><td colspan='4' class='text-ok'>Sin hangs Excel ultimos $Days dias (1000/1002).</td></tr>" }

$globalBad=($addins | Where-Object {$_.Badge -eq "warn"}).Count + $hooks.Count + (&{if($hangs.Count -gt 0){1}else{0}})
$globalBadge=if($globalBad -eq 0){"ok"}elseif($globalBad -le 2){"warn"}else{"bad"}
$globalText=if($globalBad -eq 0){"Sin hallazgos"}else{"$globalBad hallazgo(s)"}

if($OutputPath){$OutputFile=$OutputPath}else{$OutputFile=Join-Path $desktopPath ("Auditoria_Office_LIGHT_${ComputerName}_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".html")}
$computerEsc=ConvertTo-HtmlEscaped $ComputerName

$htmlContent=@"
<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Office LIGHT - $computerEsc</title>
<style>
:root{--bg:#0f172a;--card-bg:#1e293b;--card-border:#334155;--text-main:#f8fafc;--text-muted:#94a3b8;--accent-blue:#38bdf8;--ok:#22c55e;--warn:#eab308;--bad:#ef4444}
*{box-sizing:border-box;margin:0;padding:0;font-family:'Segoe UI',Tahoma,sans-serif}
body{background:var(--bg);color:var(--text-main);padding:24px;line-height:1.5}
.header{display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid var(--card-border);padding-bottom:16px;margin-bottom:24px;flex-wrap:wrap;gap:12px}
.header h1{font-size:20px;color:var(--accent-blue)}
.grid-summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px;margin-bottom:24px}
.summary-card{background:var(--card-bg);border:1px solid var(--card-border);border-radius:8px;padding:16px}
.summary-card span.label{font-size:11px;color:var(--text-muted);text-transform:uppercase;display:block;margin-bottom:4px}
.summary-card div.val{font-size:16px;font-weight:bold}
.card{background:var(--card-bg);border:1px solid var(--card-border);border-radius:8px;padding:20px;margin-bottom:24px}
.card h3{color:var(--accent-blue);margin-bottom:12px;font-size:16px;border-bottom:1px solid var(--card-border);padding-bottom:8px}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px}
th{text-align:left;background:rgba(15,23,42,0.8);color:var(--text-muted);padding:8px;border-bottom:1px solid var(--card-border)}
td{padding:8px;border-bottom:1px solid var(--card-border)}
tr.row-bad{background:rgba(239,68,68,0.08)}
.badge{display:inline-block;padding:3px 9px;border-radius:12px;font-size:11px;font-weight:bold}
.badge.ok{background:rgba(34,197,94,0.2);color:var(--ok);border:1px solid var(--ok)}
.badge.warn{background:rgba(234,179,8,0.2);color:var(--warn);border:1px solid var(--warn)}
.badge.bad{background:rgba(239,68,68,0.2);color:var(--bad);border:1px solid var(--bad)}
.text-ok{color:var(--ok)}.text-muted{color:var(--text-muted)}
.footer{text-align:center;color:var(--text-muted);font-size:11px;margin-top:30px}
</style></head>
<body>
<div class="header"><div><h1>Auditoria Office</h1><p>Equipo: <strong>$computerEsc</strong> | $ReportDate | Modo ligero</p></div><div><span class="badge $globalBadge">$globalText</span></div></div>
$(if($oneDriveWarn){"<div class='card' style='border-color:var(--warn)'><h3 style='color:var(--warn)'>Aviso OneDrive</h3><p class='text-muted'>Reporte en OneDrive sincronizado.</p></div>"})
<div class="grid-summary">
<div class="summary-card"><span class="label">Office Version</span><div class="val">$(ConvertTo-HtmlEscaped $officeInfo.VersionToReport)</div><p style="font-size:11px;color:var(--text-muted)">$(ConvertTo-HtmlEscaped $officeInfo.UpdateChannel)</p></div>
<div class="summary-card"><span class="label">Aceleracion Gfx</span><div class="val"><span class="badge $($gfx.Badge)">$(ConvertTo-HtmlEscaped $gfx.AceleracionGrafica)</span></div></div>
<div class="summary-card"><span class="label">COM Add-ins</span><div class="val">$($addins.Count) detectados</div></div>
<div class="summary-card"><span class="label">Portapapeles</span><div class="val"><span class="badge $clipBadge">LIGHT</span></div><p style="font-size:11px;color:var(--text-muted)">Historial: $clipHistEsc</p></div>
</div>

<div class="card"><h3>Notas</h3><p class="text-muted" style="font-size:13px">Modo ligero: solo consulta registro y lista reducida de procesos. Para diagnostico detallado usa <code>-IncludeClipboardCheck</code> o la version completa.</p></div>

<div class="card"><h3>1. Office Instalado</h3><table><thead><tr><th>App</th><th>Version</th><th>Ruta</th></tr></thead><tbody>$officeRows</tbody></table></div>
<div class="card"><h3>2. COM Add-ins (LoadBehavior)</h3><table><thead><tr><th>Nombre</th><th>Estado</th><th>LB</th><th>Registro</th></tr></thead><tbody>$addinRows</tbody></table></div>
<div class="card"><h3>3. Resiliency / DisabledItems</h3><table><thead><tr><th>Area</th><th>Nombre</th><th>Detalle</th></tr></thead><tbody>$resRows</tbody></table></div>
<div class="card"><h3>4. Aceleracion Grafica</h3><table><tbody><tr><td>Estado</td><td><span class="badge $($gfx.Badge)">$(ConvertTo-HtmlEscaped $gfx.AceleracionGrafica)</span></td><td class="text-muted">$(ConvertTo-HtmlEscaped $gfx.PathRegistry)</td></tr></tbody></table></div>
<div class="card"><h3>5. XLSTART / STARTUP</h3><table><thead><tr><th>Archivo</th><th>Tamano</th><th>Fecha</th><th>Estado</th></tr></thead><tbody>$xlRows</tbody></table></div>
<div class="card"><h3>6. Procesos relacionados con portapapeles</h3><table><thead><tr><th>Proceso</th><th>PID</th><th>Estado</th></tr></thead><tbody>$hookRows</tbody></table></div>
<div class="card"><h3>7. Portapapeles</h3><table><tbody>
<tr><td>Historial Windows</td><td>$clipHistEsc</td><td class="text-muted">HKCU\Software\Microsoft\Clipboard</td></tr>
<tr><td>Preview</td><td style="word-break:break-all;">$clipPrevEsc</td><td class="text-muted">$clipNotaEsc</td></tr>
</tbody></table></div>
<div class="card"><h3>8. Excel en Ejecucion</h3><table><thead><tr><th>PID</th><th>RAM</th><th>Handles</th><th>Estado</th></tr></thead><tbody>$excelRows</tbody></table></div>
<div class="card"><h3>9. Hangs Excel (ultimos $Days dias)</h3><table><thead><tr><th>Fecha</th><th>Origen</th><th>ID</th><th>Resumen</th></tr></thead><tbody>$hangRows</tbody></table></div>
<div class="card"><h3>10. Reinicio Pendiente</h3><table><tbody>$pendingRows</tbody></table></div>

<div class="footer">WindowsDiagnosis $ReportDate | Host $computerEsc</div>
</body></html>
"@

try{ [System.IO.File]::WriteAllText($OutputFile, $htmlContent, [System.Text.Encoding]::UTF8) } catch {
    if($PSVersionTable.PSVersion.Major -ge 6){ $htmlContent | Out-File -FilePath $OutputFile -Encoding utf8BOM -Force } else { $htmlContent | Out-File -FilePath $OutputFile -Encoding utf8 -Force }
}
Write-Host "`nReporte LIGHT generado: $OutputFile" -ForegroundColor Green
try{ $h=(Get-FileHash -Path $OutputFile -Algorithm SHA256 -ErrorAction Stop).Hash; Write-Host "SHA256: $h" -ForegroundColor Gray } catch {}
if(-not $NoOpen){ try{ Start-Process $OutputFile -ErrorAction Stop } catch{ Write-Host "Abre manual: $OutputFile" -ForegroundColor Yellow } }
if(($addins | Where-Object {$_.Badge -eq "warn"}).Count -gt 0 -or $hooks.Count -gt 0){ exit 1 } else { exit 0 }
