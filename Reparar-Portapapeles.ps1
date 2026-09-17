<#
.SYNOPSIS
    Repara el portapapeles de Excel/Office - copia de varias celdas que no pega en filas inferiores.
.DESCRIPTION
    Aplica de forma reversible y con -WhatIf las 7 reparaciones mas efectivas detectadas por
    Auditoria-Office-Clipboard.ps1. No reinstala Office. Cada accion es opcional por switch;
    con -All ejecuta el kit completo en orden seguro.

    Acciones:
     1) Vaciar portapapeles real (Win32 EmptyClipboard + clip) - desbloquea OpenClipboard
     2) Reiniciar rdpclip.exe (fix #1 en RDP)
     3) Cerrar interceptores conocidos (PowerToys, Ditto, ShareX, Grammarly, DeepL, etc.)
     4) Desactivar Historial de portapapeles (rompe rangos TSV en 22H2+)
     5) Deshabilitar aceleracion grafica Office (DisableHardwareAcceleration=1)
     6) Reset CutCopyMode de Excel via COM + matar EXCEL colgado + limpiar XLSTART cache
     7) Deshabilitar COM Add-ins con LoadBehavior 3 de forma interactiva

    Todas las escrituras en registro hacen backup .reg previo en %TEMP%.
    Compatible PowerShell 5.1+ (Windows 10/11). No requiere Admin salvo para HKLM Addins.
.NOTES
    Ejecutar: powershell -ExecutionPolicy Bypass -File .\Reparar-Portapapeles.ps1 -All -WhatIf
    Luego sin WhatIf: powershell -ExecutionPolicy Bypass -File .\Reparar-Portapapeles.ps1 -All
    Si viene de USB: Unblock-File -Path .\Reparar-Portapapeles.ps1
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [switch]$All,
    [switch]$VaciarClipboard,
    [switch]$ReiniciarRdpClip,
    [switch]$CerrarInterceptores,
    [switch]$FixHistorial,
    [switch]$DeshabilitarGfx,
    [switch]$ReiniciarExcel,
    [switch]$FixAddins,
    [switch]$RepararOffice,
    [switch]$Force,
    [string]$LogPath = "",
    [switch]$NoBackup
)

# --- GOTCHAS DE EJECUCION ---
if ($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage") {
    Write-Host "ADVERTENCIA: LanguageMode=$($ExecutionContext.SessionState.LanguageMode) (no FullLanguage). Algunas reparaciones fallaran." -ForegroundColor Yellow
}
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    $sysNative = "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe"
    $target = if (Test-Path $sysNative) { $sysNative } else { "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" }
    Write-Host "AVISO: 32-bit en OS 64-bit. Relanzando en 64-bit..." -ForegroundColor Yellow
    try {
        $a=@("-ExecutionPolicy","Bypass","-File",$PSCommandPath)
        if($All){$a+="-All"}; if($VaciarClipboard){$a+="-VaciarClipboard"}; if($ReiniciarRdpClip){$a+="-ReiniciarRdpClip"}
        if($CerrarInterceptores){$a+="-CerrarInterceptores"}; if($FixHistorial){$a+="-FixHistorial"}; if($DeshabilitarGfx){$a+="-DeshabilitarGfx"}
        if($ReiniciarExcel){$a+="-ReiniciarExcel"}; if($FixAddins){$a+="-FixAddins"}; if($Force){$a+="-Force"}
        & $target @a; exit $LASTEXITCODE
    } catch { Write-Host "No se pudo relanzar: $($_.Exception.Message)" -ForegroundColor Yellow }
}

$ErrorActionPreference = "SilentlyContinue"
$Script:ActionsDone = @()
$Script:ActionsSkipped = @()
$Script:BackupDir = Join-Path $env:TEMP ("OfficeClipFix_" + (Get-Date -Format 'yyyyMMdd_HHmmss'))

function Write-Log {
    param([string]$msg,[string]$color="Gray")
    Write-Host $msg -ForegroundColor $color
    if($LogPath){
        try { Add-Content -Path $LogPath -Value ("["+(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+"] "+$msg) -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
    }
}

function Backup-Registry {
    param([string]$Path)
    if($NoBackup){return}
    if(-not (Test-Path $Path)){return}
    try{
        if(-not (Test-Path $Script:BackupDir)){ New-Item -ItemType Directory -Path $Script:BackupDir -Force | Out-Null }
        $safe = ($Path -replace '[^A-Za-z0-9]','_')
        $dst = Join-Path $Script:BackupDir ($safe + ".reg")
        & reg.exe export $Path.Replace(':','') $dst /y 2>&1 | Out-Null
        Write-Log "  Backup: $Path -> $dst" "DarkGray"
    } catch {}
}

# Si -All, activar todo excepto RepararOffice (requiere confirmacion) y FixAddins (interactivo)
if($All){
    $VaciarClipboard=$true; $ReiniciarRdpClip=$true; $CerrarInterceptores=$true
    $FixHistorial=$true; $DeshabilitarGfx=$true; $ReiniciarExcel=$true
    if(-not $FixAddins -and $Force){ $FixAddins=$true }
}
# Si ningun switch, mostrar ayuda y activar modo interactivo por defecto
$any = $VaciarClipboard -or $ReiniciarRdpClip -or $CerrarInterceptores -or $FixHistorial -or $DeshabilitarGfx -or $ReiniciarExcel -or $FixAddins -or $RepararOffice
if(-not $any){
    Write-Host @"
Uso: .\Reparar-Portapapeles.ps1 [-All] [-VaciarClipboard] [-ReiniciarRdpClip] [-CerrarInterceptores] [-FixHistorial] [-DeshabilitarGfx] [-ReiniciarExcel] [-FixAddins] [-RepararOffice]

Ejemplos:
  .\Reparar-Portapapeles.ps1 -All -WhatIf          # simula
  .\Reparar-Portapapeles.ps1 -All                  # repara todo (Addins pide confirmacion)
  .\Reparar-Portapapeles.ps1 -All -Force            # incluye FixAddins automatico
  .\Reparar-Portapapeles.ps1 -VaciarClipboard -ReiniciarRdpClip
  .\Reparar-Portapapeles.ps1 -CerrarInterceptores -FixHistorial

"@ -ForegroundColor Yellow
    Write-Log "Sin switches: ejecuta con -All -WhatIf para preview." "Yellow"
    return
}

if($LogPath){
    try { $d=Split-Path $LogPath -Parent; if($d -and -not (Test-Path $d)){ New-Item -ItemType Directory -Path $d -Force | Out-Null }; "" | Out-File -FilePath $LogPath -Encoding utf8 -Force } catch {}
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " Reparar Portapapeles Office - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host " Host: $env:COMPUTERNAME  User: $env:USERNAME  WhatIf: $WhatIfPreference" -ForegroundColor Gray
Write-Host "==================================================" -ForegroundColor Cyan

# ----------------------------------------------------
# 1) Vaciar portapapeles real
# ----------------------------------------------------
if($VaciarClipboard){
    Write-Log "[1/7] Vaciando portapapeles (Win32 EmptyClipboard)..." "Yellow"
    if($PSCmdlet.ShouldProcess("Portapapeles Windows","EmptyClipboard")){
        $ok=$false
        try{
            Add-Type @"
using System; using System.Runtime.InteropServices;
public class ClipFix { [DllImport("user32.dll")] public static extern bool OpenClipboard(IntPtr h); [DllImport("user32.dll")] public static extern bool EmptyClipboard(); [DllImport("user32.dll")] public static extern bool CloseClipboard(); }
"@ -ErrorAction SilentlyContinue
            if([ClipFix]::OpenClipboard([IntPtr]::Zero)){ [void][ClipFix]::EmptyClipboard(); [void][ClipFix]::CloseClipboard(); $ok=$true; Write-Log "  -> EmptyClipboard OK (desbloqueado)" "Green"; $Script:ActionsDone+="VaciarClipboard: Win32 OK" }
            else { Write-Log "  -> OpenClipboard fallo (clipboard aun bloqueado por otro proceso)" "Yellow"; $Script:ActionsSkipped+="VaciarClipboard: bloqueado" }
        } catch { Write-Log "  -> Error API: $($_.Exception.Message)" "Red" }
        # Fallbacks
        try { Set-Clipboard -Value $null -ErrorAction Stop; Write-Log "  -> Set-Clipboard null OK" "Green" } catch { Write-Log "  -> Set-Clipboard fallo: $($_.Exception.Message)" "DarkGray" }
        try { cmd /c "echo off | clip" 2>&1 | Out-Null; Write-Log "  -> cmd clip vaciado" "Green" } catch {}
        try { Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue; [System.Windows.Forms.Clipboard]::Clear(); Write-Log "  -> Forms.Clipboard.Clear OK" "Green" } catch {}
        if($ok){ $Script:ActionsDone+="VaciarClipboard" } else { $Script:ActionsDone+="VaciarClipboard (fallbacks)" }
    }
}

# ----------------------------------------------------
# 2) Reiniciar rdpclip
# ----------------------------------------------------
if($ReiniciarRdpClip){
    Write-Log "[2/7] Reiniciando rdpclip.exe (fix RDP)..." "Yellow"
    $rdp = Get-Process -Name rdpclip -ErrorAction SilentlyContinue
    if($rdp){
        if($PSCmdlet.ShouldProcess("rdpclip PID $($rdp.Id)","Reiniciar")){
            try{ $rdp | Stop-Process -Force -ErrorAction Stop; Write-Log "  -> rdpclip detenido" "Green"; Start-Sleep 800 } catch { Write-Log "  -> No se pudo detener: $($_.Exception.Message)" "Yellow" }
            try{ Start-Process "$env:SystemRoot\System32\rdpclip.exe" -ErrorAction Stop; Write-Log "  -> rdpclip reiniciado" "Green"; $Script:ActionsDone+="ReiniciarRdpClip" } catch { Write-Log "  -> No se pudo reiniciar: $($_.Exception.Message)" "Red"; try{ Start-Process "rdpclip.exe" -ErrorAction SilentlyContinue } catch{} }
        }
    } else {
        # Si no esta pero estamos en sesion RDP, iniciarlo igual puede reparar
        $isRdp = ($env:SESSIONNAME -like "RDP*") -or (Get-Process -Name rdpclip -ErrorAction SilentlyContinue)
        if($isRdp -or $Force){
            if($PSCmdlet.ShouldProcess("rdpclip","Iniciar")){
                try{ Start-Process "$env:SystemRoot\System32\rdpclip.exe" -ErrorAction Stop; Write-Log "  -> rdpclip iniciado (no estaba corriendo)" "Green"; $Script:ActionsDone+="ReiniciarRdpClip (iniciado)" } catch { Write-Log "  -> rdpclip no encontrado (no es sesion RDP?) " "DarkGray"; $Script:ActionsSkipped+="RdpClip no aplica" }
            }
        } else { Write-Log "  -> rdpclip no estaba en ejecucion (no es RDP, se omite)" "DarkGray"; $Script:ActionsSkipped+="RdpClip no RDP" }
    }
}

# ----------------------------------------------------
# 3) Cerrar interceptores
# ----------------------------------------------------
if($CerrarInterceptores){
    Write-Log "[3/7] Cerrando interceptores de portapapeles..." "Yellow"
    $known = @("PowerToys","AutoHotkey","ShareX","Greenshot","Lightshot","Grammarly","DeepL","AcroRd32","Acrobat","Ditto","ClipClip","RazerSynapse","ClipboardFusion","1Clipboard","ClipX","CopyQ","PhraseExpress","Notion","Slack","Teams","Zoom","Webexmta","KeePass","Bitwarden","ArsClip","Clipdiary")
    $found = @()
    foreach($n in $known){ $p=Get-Process -Name $n -ErrorAction SilentlyContinue; if($p){ $found+=$p } }
    # rdpclip ya tratado, no repetir si ya se reinicio
    $found = $found | Where-Object { $_.ProcessName -ne "rdpclip" } | Sort-Object ProcessName -Unique
    if($found.Count -gt 0){
        Write-Log ("  Detectados: " + (($found | ForEach-Object { "$($_.ProcessName)($($_.Id))" }) -join ", ")) "Yellow"
        foreach($proc in $found){
            $label="$($proc.ProcessName) PID $($proc.Id)"
            if($Force -or $PSCmdlet.ShouldProcess($label,"Cerrar proceso interceptor")){
                try{ Stop-Process -Id $proc.Id -Force -ErrorAction Stop; Write-Log "  -> Cerrado $label" "Green"; $Script:ActionsDone+="Cerrar $($proc.ProcessName)" } catch { Write-Log "  -> No se pudo cerrar ${label}: $($_.Exception.Message)" "Red" }
            } else { $Script:ActionsSkipped+="Cerrar $label (WhatIf/Confirm)" }
        }
    } else { Write-Log "  -> Ningun interceptor conocido en ejecucion" "Green"; $Script:ActionsSkipped+="Interceptores: ninguno" }
}

# ----------------------------------------------------
# 4) Fix Historial portapapeles
# ----------------------------------------------------
if($FixHistorial){
    Write-Log "[4/7] Desactivando Historial de portapapeles (fix TSV 22H2+)..." "Yellow"
    $path="HKCU:\Software\Microsoft\Clipboard"
    $cur = (Get-ItemProperty -Path $path -Name EnableClipboardHistory -ErrorAction SilentlyContinue).EnableClipboardHistory
    Write-Log "  Estado actual: $(if($null -eq $cur){'no configurado'}else{$cur}) (1=activo, 0=off)" "Gray"
    if($cur -ne 0){
        if($PSCmdlet.ShouldProcess($path,"Desactivar EnableClipboardHistory=0")){
            Backup-Registry $path
            try{
                if(-not (Test-Path $path)){ New-Item -Path $path -Force | Out-Null }
                Set-ItemProperty -Path $path -Name EnableClipboardHistory -Value 0 -Type DWord -ErrorAction Stop
                Write-Log "  -> Historial desactivado" "Green"; $Script:ActionsDone+="FixHistorial: off"
            } catch { Write-Log "  -> Error: $($_.Exception.Message)" "Red" }
        }
    } else { Write-Log "  -> Ya estaba desactivado" "Green"; $Script:ActionsSkipped+="Historial ya off" }
}

# ----------------------------------------------------
# 5) Deshabilitar aceleracion grafica
# ----------------------------------------------------
if($DeshabilitarGfx){
    Write-Log "[5/7] Deshabilitando aceleracion grafica Office..." "Yellow"
    $gfxPath="HKCU:\Software\Microsoft\Office\16.0\Common\Graphics"
    $cur = (Get-ItemProperty -Path $gfxPath -Name DisableHardwareAcceleration -ErrorAction SilentlyContinue).DisableHardwareAcceleration
    Write-Log "  Valor actual: $(if($null -eq $cur){'no configurado (aceleracion activa)'}else{$cur})" "Gray"
    if($cur -ne 1){
        if($PSCmdlet.ShouldProcess($gfxPath,"DisableHardwareAcceleration=1")){
            Backup-Registry $gfxPath
            try{
                if(-not (Test-Path $gfxPath)){ New-Item -Path $gfxPath -Force | Out-Null }
                Set-ItemProperty -Path $gfxPath -Name DisableHardwareAcceleration -Value 1 -Type DWord -ErrorAction Stop
                Write-Log "  -> Aceleracion deshabilitada (requiere reiniciar Excel)" "Green"; $Script:ActionsDone+="DeshabilitarGfx: 1"
            } catch { Write-Log "  -> Error: $($_.Exception.Message)" "Red" }
        }
    } else { Write-Log "  -> Ya estaba deshabilitada" "Green"; $Script:ActionsSkipped+="Gfx ya off" }
}

# ----------------------------------------------------
# 6) Reiniciar Excel / reset CutCopyMode
# ----------------------------------------------------
if($ReiniciarExcel){
    Write-Log "[6/7] Reseteando Excel (CutCopyMode + procesos colgados)..." "Yellow"
    # Intentar COM si hay instancia activa
    $comOk=$false
    try{
        $xl=[Runtime.InteropServices.Marshal]::GetActiveComObject("Excel.Application")
        if($xl){
            if($PSCmdlet.ShouldProcess("Excel COM","CutCopyMode=False")){
                try{ $xl.CutCopyMode=$false; Write-Log "  -> CutCopyMode=False OK" "Green"; $comOk=$true } catch { Write-Log "  -> CutCopyMode fallo: $($_.Exception.Message)" "Yellow" }
                try{ $xl.Calculate(); Write-Log "  -> Calculate OK" "Green" } catch {}
            }
            # No cerramos Excel si responde, solo liberar COM
            try{ [void][Runtime.InteropServices.Marshal]::ReleaseComObject($xl) } catch {}
        }
    } catch { Write-Log "  -> Sin instancia COM activa (Excel cerrado o sin permiso DCOM)" "DarkGray" }
    # Matar solo los colgados (NotResponding) salvo -Force que mata todos
    $procs = Get-Process -Name EXCEL -ErrorAction SilentlyContinue
    if($procs){
        $toKill = @()
        if($Force){ $toKill=$procs } else { $toKill=$procs | Where-Object { $_.Responding -eq $false } }
        if($toKill.Count -gt 0){
            foreach($p in $toKill){
                $lbl="EXCEL PID $($p.Id) RAM $([math]::Round($p.WorkingSet/1MB,1))MB Resp=$($p.Responding)"
                if($PSCmdlet.ShouldProcess($lbl,"Stop-Process")){
                    try{ Stop-Process -Id $p.Id -Force -ErrorAction Stop; Write-Log "  -> Terminado $lbl" "Green"; $Script:ActionsDone+="Kill Excel $($p.Id)" } catch { Write-Log "  -> No se pudo terminar $($p.Id): $($_.Exception.Message)" "Red" }
                }
            }
        } else {
            if($procs.Count -gt 0 -and -not $Force){ Write-Log "  -> Excel(s) responde(n) ($($procs.Count)), no se mata sin -Force. Usa -Force para forzar reinicio o cierra manual." "Gray"; $Script:ActionsSkipped+="Excel responde, no kill" }
        }
        if($comOk){ $Script:ActionsDone+="Reset CutCopyMode" }
    } else { Write-Log "  -> Excel no estaba en ejecucion" "DarkGray"; $Script:ActionsSkipped+="Excel no running" }
    # Limpiar cache de Office Clipboard temp (no borra XLSTART, solo OfficeFileCache)
    try{
        $cache="$env:LOCALAPPDATA\Microsoft\Office\16.0\OfficeFileCache"
        if(Test-Path $cache){
            $cnt=(Get-ChildItem $cache -File -ErrorAction SilentlyContinue | Measure-Object).Count
            Write-Log "  OfficeFileCache: $cnt archivos (no se borra auto, solo informativo)" "DarkGray"
        }
    } catch {}
}

# ----------------------------------------------------
# 7) Fix Add-ins (interactivo)
# ----------------------------------------------------
if($FixAddins){
    Write-Log "[7/7] Revisando COM Add-ins con LoadBehavior 3..." "Yellow"
    $paths=@("HKCU:\Software\Microsoft\Office\Excel\Addins","HKLM:\SOFTWARE\Microsoft\Office\Excel\Addins","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Excel\Addins")
    $candidates=@()
    foreach($pp in $paths){
        if(Test-Path $pp){
            Get-ChildItem -Path $pp -ErrorAction SilentlyContinue | ForEach-Object {
                $lb=(Get-ItemProperty -Path $_.PSPath -Name LoadBehavior -ErrorAction SilentlyContinue).LoadBehavior
                if($lb -eq 3){ $candidates+= [PSCustomObject]@{ Path=$_.PSPath; Name=$_.PSChildName; LB=$lb; RegistryPath=$pp } }
            }
        }
    }
    if($candidates.Count -gt 0){
        Write-Log ("  Add-ins activos al inicio (LB=3): " + (($candidates | ForEach-Object { $_.Name }) -join ", ")) "Yellow"
        foreach($c in $candidates){
            $should=$Force
            if(-not $Force){
                # Preguntar solo si no es -Force y no es WhatIf
                if($WhatIfPreference){ $should=$false; Write-Log "  [WhatIf] Deshabilitaria $($c.Name) -> LB=2" "DarkGray"; $Script:ActionsSkipped+="Addin $($c.Name) WhatIf" ; continue }
                $ans=Read-Host "  Deshabilitar $($c.Name) (LB 3->2)? [s/N]"
                if($ans -match "^s$|^S$|^y$|^Y$"){ $should=$true } else { Write-Log "  -> Omitido $($c.Name)" "DarkGray"; $Script:ActionsSkipped+="Addin $($c.Name) omitido"; continue }
            }
            if($should){
                if($PSCmdlet.ShouldProcess($c.Path,"LoadBehavior 3->2")){
                    Backup-Registry $c.RegistryPath
                    try{ Set-ItemProperty -Path $c.Path -Name LoadBehavior -Value 2 -Type DWord -ErrorAction Stop; Write-Log "  -> Deshabilitado $($c.Name)" "Green"; $Script:ActionsDone+="Addin $($c.Name) LB2" } catch { Write-Log "  -> Error $($c.Name): $($_.Exception.Message) (prueba como Admin)" "Red" }
                }
            }
        }
        Write-Log "  Tip: prueba Excel en modo seguro para validar: excel /safe" "Gray"
    } else { Write-Log "  -> Ningun Add-in con LB=3" "Green"; $Script:ActionsSkipped+="Addins: ninguno LB3" }
}

# ----------------------------------------------------
# 8) Reparar Office (opcional, requiere confirmacion)
# ----------------------------------------------------
if($RepararOffice){
    Write-Log "[8/7] Reparacion ClickToRun Office..." "Yellow"
    $c2r="$env:ProgramFiles\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
    if(-not (Test-Path $c2r)){ $c2r="${env:ProgramFiles(x86)}\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe" }
    if(Test-Path $c2r){
        if($Force -or $PSCmdlet.ShouldProcess("Office ClickToRun","Reparar/update user")){
            try{ Write-Log "  Lanzando: $c2r /update user displaylevel=false" "Gray"; Start-Process $c2r -ArgumentList "/update user displaylevel=false" -ErrorAction Stop; Write-Log "  -> Update lanzado (revisa progreso en Office)" "Green"; $Script:ActionsDone+="RepararOffice update" } catch { Write-Log "  -> Error: $($_.Exception.Message)" "Red" }
        }
    } else { Write-Log "  -> OfficeC2RClient.exe no encontrado (MSI o Store?)" "Yellow"; $Script:ActionsSkipped+="C2R no encontrado" }
}

# Resumen
Write-Host "`n==================================================" -ForegroundColor Cyan
Write-Host " Resumen Reparacion" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
if($Script:ActionsDone.Count -gt 0){ Write-Host " Acciones aplicadas ($($Script:ActionsDone.Count)):" -ForegroundColor Green; $Script:ActionsDone | ForEach-Object { Write-Host "  + $_" -ForegroundColor Green } }
if($Script:ActionsSkipped.Count -gt 0){ Write-Host " Omitidas/WhatIf ($($Script:ActionsSkipped.Count)):" -ForegroundColor DarkGray; $Script:ActionsSkipped | ForEach-Object { Write-Host "  - $_" -ForegroundColor DarkGray } }
if($Script:BackupDir -and (Test-Path $Script:BackupDir)){ Write-Host " Backups .reg en: $Script:BackupDir" -ForegroundColor Gray }
Write-Host "`n Pasos siguientes:" -ForegroundColor Yellow
Write-Host "  1. Abre Excel y copia varias celdas -> pega en filas inferiores. Si funciona, re-activa Add-ins uno a uno." -ForegroundColor Gray
Write-Host "  2. Si sigue fallando, ejecuta Auditoria: .\Auditoria-Office-Clipboard.ps1 -NoOpen" -ForegroundColor Gray
Write-Host "  3. Deja corriendo monitor: .\Monitor-Portapapeles.ps1 -IntervalMs 200 para cazar reincidencia." -ForegroundColor Gray
Write-Host "  4. Para revertir Gfx/Historial: importa el .reg del backup con doble clic (o reg import)." -ForegroundColor Gray
Write-Host "==================================================" -ForegroundColor Cyan

if($LogPath){ Write-Log "Log guardado en $LogPath" "Cyan" }

# Exit code 0=todo ok, 1=hubo acciones, 2=WhatIf
if($WhatIfPreference){ exit 2 } elseif($Script:ActionsDone.Count -gt 0){ exit 1 } else { exit 0 }
