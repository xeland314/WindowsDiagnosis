# WindowsDiagnosis — Diagnostico, Auditoria y Cumplimiento LOPDP para Windows

> Seis scripts **PowerShell sin dependencias** que generan reportes **HTML portables** (CSS inline, sin CDN/JS) para soporte tecnico, caza de persistencia, auditoria **LOPDP Art. 10 y 38** (Ecuador) y diagnostico/reparacion de **Office/Excel/portapapeles**. Compatibles **Windows 10 21H2+ / Windows 11** con **PowerShell 5.1** (Desktop) y **7+** (Core).

> **Sin tildes en codigo ni en HTML:** todo ASCII para que PowerShell 5.1 —que lee `.ps1` como ANSI si no tiene BOM— no rompa `Write-Host` ni comentarios al copiar desde USB. El HTML sigue declarando `UTF-8` (`<meta charset="UTF-8">` + `http-equiv`) y se escribe con `[System.IO.File]::WriteAllText(..., UTF8)` (con BOM) para Notepad/navegador, pero el contenido evita diacriticos y evita mojibake en `file://`.

---

## Indice

- [Scripts](#scripts)
- [Diagnostico-PC-HTML.ps1 — 12 bloques](#diagnostico-pc-htmlps1---12-bloques)
- [Auditoria-Autoarranque.ps1 — 10 bloques](#auditoria-autoarranqueps1---10-bloques-persistencia-y-caza-de-amenazas)
- [Auditoria-LOPDP-Endpoint.ps1 — 5 bloques](#auditoria-lopdp-endpointps1---5-bloques-cumplimiento-lopdp)
- [Auditoria-Office-Clipboard.ps1 — 12 bloques (Office/portapapeles)](#auditoria-office-clipboardps1---12-bloques-officeportapapeles)
- [Monitor-Portapapeles.ps1 — tiempo real](#monitor-portapapelesps1---tiempo-real)
- [Reparar-Portapapeles.ps1 — reparacion](#reparar-portapapelesps1---reparacion)
- [Puntos ciegos cubiertos](#puntos-ciegos-cubiertos)
- [Requisitos y compatibilidad](#requisitos-y-compatibilidad)
- [Uso rapido](#uso-rapido)
- [Estructura del repo y builders](#estructura-del-repo-y-builders)
- [FAQ](#faq)

---

## Scripts

| Script | Proposito | Salida HTML | Cuando usarlo |
|--------|-----------|-------------|---------------|
| `Diagnostico-PC-HTML.ps1` | **Salud tecnica** del equipo (hardware, SO, red, updates) | `Desktop\Diagnostico_<HOST>_<fecha>.html` | Ticket de lentitud, inventario, entrega a usuario/soporte |
| `Auditoria-Autoarranque.ps1` | **Persistencia y masquerading** T1036/T1496/T1546.003 — caso FAHConsole en WinZip | `Desktop\Auditoria_Autoarranque_<HOST>_<fecha>.html` | Sospecha de minero/PUP, DFIR, revision de autoarranque |
| `Auditoria-LOPDP-Endpoint.ps1` | **Cumplimiento LOPDP Art.10/38** — 10 bloques (BitLocker, puertos, Firewall, AV, admins + bloqueo, cuentas, LAPS/NLA/SMB, remote/logs/EOL, Defender+/SecureBoot) | `Desktop\Auditoria_LOPDP_<HOST>_<fecha>.html` | Auditoria legal, visita Superintendencia, rodo de laptops contables |
| `Auditoria-Office-Clipboard.ps1` | **Office/Excel + portapapeles** — copia de varias celdas que no pega en filas inferiores | `Desktop\Auditoria_Office_<HOST>_<fecha>.html` | Excel se cuelga al copiar, portapapeles vacio/bloqueado, Add-ins, Gfx, XLSTART |
| `Monitor-Portapapeles.ps1` | **Monitor tiempo real** del portapapeles (GetClipboardOwner) | Consola + opcional `clip.csv` | Ver en vivo si otro programa roba el clipboard tras Ctrl+C en Excel |
| `Reparar-Portapapeles.ps1` | **Reparacion** reversible con `-WhatIf` (7 fixes) | Consola + backup `.reg` en `%TEMP%` | Aplicar fix tras auditar: rdpclip, vaciar clipboard, historial, Gfx, CutCopyMode, Add-ins |

Builders (solo desarrollo, no necesarios para ejecutar):

| Builder | Genera |
|---------|--------|
| `tools/build_diagnostico.py` | `Diagnostico-PC-HTML.ps1` (888 lineas, ASCII) |
| `tools/build_auditoria.py` | `Auditoria-Autoarranque.ps1` (1262 lineas, ASCII, details cards) |
| `tools/build_lopdp.py` | `Auditoria-LOPDP-Endpoint.ps1` (1026 lineas, ASCII) |

```powershell
# Regenerar tras editar el builder:
python tools/build_diagnostico.py
python tools/build_auditoria.py
python tools/build_lopdp.py
```

---

## Diagnostico-PC-HTML.ps1 — 12 bloques

| # | Bloque | Fuente | Que muestra | Alerta |
|---|--------|--------|-------------|--------|
| 1 | Sistema y CPU | `Win32_OperatingSystem`, `Win32_Processor`, `Get-Counter` (`\Processor(_Total)\% Processor Time` + fallback `\Procesador(_Total)\% de tiempo de procesador`) | Nombre/version Windows, uptime, CPU modelo/nucleos/hilos, % carga | `bad` >85% |
| 2 | Memoria RAM | `Win32_OperatingSystem`, `Get-Counter` (`\Memory\Available MBytes` / `\Memoria\Mbytes disponibles`), `Win32_PhysicalMemory` | RAM total/libre/usada %, disponible real descontando cache, tabla por ranura | `bad` >90% |
| 3 | Controladores | `Get-PnpDevice` | Dispositivos `Status != OK` con `ConfigManagerErrorCode` | `bad` si hay fallos |
| 4 | Bateria | `Win32_Battery` + `powercfg /batteryreport` (parse `DESIGN CAPACITY`/`FULL CHARGE`) | % salud / % desgaste | `bad` desgaste >35% |
| 5 | Almacenamiento fisico | `Get-PhysicalDisk` | ID, modelo, MediaType (HDD/SSD/NVMe), capacidad, `HealthStatus` S.M.A.R.T. | `bad` si != Healthy |
| 6 | **Volumenes logicos** | `Win32_LogicalDisk` DriveType=3 | Unidad, etiqueta, FS, capacidad/libre/usado, % libre | `bad` <10% libre, `warn` <20% |
| 7 | **GPU** | `Win32_VideoController` | Modelo, VideoProcessor, VRAM, DriverVersion, resolucion | info |
| 8 | **Red** | `Get-NetAdapter` (fallback `Win32_NetworkAdapter`) + `Get-NetIPAddress` + `Test-Connection 1.1.1.1 / 8.8.8.8` | Adaptadores activos/MAC/LinkSpeed, IPv4, conectividad | `bad` si sin respuesta |
| 9 | Visor de eventos (48h) | `Get-WinEvent` System+Application Level 1/2 | Top 8 criticos + tabla WHEA (`WHEA*`, `*memory*`, ID 1001) | distingue "sin eventos" vs "sin permisos" |
| 10 | **Defender / AV** | `Get-MpComputerStatus` fallback `root/SecurityCenter2` | AV habilitado, tiempo real, fecha firma, motor | `bad` si off o firmas >7d |
| 11 | **Windows Update** | `Microsoft.Update.Session` COM `Search("IsInstalled=0")` | Conteo pendientes, top 10 titulo/KB | `bad` >10 |
| 12 | Software desactualizado | `winget upgrade --include-unknown --accept-source-agreements` | Top 10 paquetes | `warn` si hay updates |

HTML oscuro con `grid-summary` + `card` + `badge ok/warn/bad`, escapado via `[System.Net.WebUtility]::HtmlEncode` (`ConvertTo-HtmlEscaped`).

---

## Auditoria-Autoarranque.ps1 — 10 bloques (persistencia y caza de amenazas)

Basado en **FAHConsole.exe** — binario legitimo firmado (0/70 VT) implantado en `C:\Program Files\WinZip\` sin relacion con WinZip. La anomalia es de **ubicacion**, no de firma.

| # | Bloque | Fuente | Que detecta |
|---|--------|--------|-------------|
| 1 | Fuentes de autoarranque | `Win32_StartupCommand` + `Get-ScheduledTask` Logon/BootTrigger + `Win32_Service` Auto | Run/RunOnce HKLM+HKCU, Carpeta Inicio, Tareas, Servicios |
| 2 | Auditoria de binarios | `VersionInfo` + `Get-AuthenticodeSignature` + `Get-FileHash SHA256` + `Test-VendorFolderMismatch` (compara `Program Files\<vendor>` vs `CompanyName/ProductName`) | Masquerading, firma, IOC |
| 3 | Throttling CPU | `Win32_Processor` Max/Current Clock | Alerta <60% (carga sostenida en 2do plano) |
| 4 | Top procesos CPU | `Get-Process` sorted `CPU` | Top 10 + RAM + ruta |
| 5 | **WMI subscriptions T1546.003** | `root/subscription: __EventFilter`, `CommandLineEventConsumer`, `ActiveScriptEventConsumer`, `__FilterToConsumerBinding` | Persistencia sin archivo — el punto ciego mas grave de `Win32_StartupCommand` |
| 6 | **Exclusiones Defender** | `Get-MpPreference` ExclusionPath/Process/Extension/IpAddress | `bad` si `WinZip`/`Temp`/`AppData` o `exe` excluido sin autorizacion |
| 7 | **Conexiones de red** | `Get-NetTCPConnection -State Established` (fallback `netstat -ano`) + `Get-Process` | Mapeo Local→Remoto→PID→Nombre, flag puertos Stratum 3333/4444/5555/7777/14444 |
| 8 | **Extensiones navegador** | `...\Chrome\User Data\Default\Extensions\*`, `...\Edge\...`, `...\Brave\...` + `HKLM\...\ExtensionSettings` | Cryptojacking via extension (mas comun que binario nativo) |
| 9 | **StartupApproved** | `HKCU/HKLM\...\Explorer\StartupApproved\Run` + `StartupFolder` (byte 0 = 0x02 Habilitado / 0x03 Deshabilitado) | Evita falsos positivos de lo ya deshabilitado por el usuario |
| 10 | **IFEO / AppInit_DLLs** | `HKLM\...\Image File Execution Options` (Debugger/VerifierDlls) + `HKLM\...\Windows\AppInit_DLLs` | Hijacking T1546.012 / DLL injection global |

`$KnownIOCHashes` con SHA256 de `FAHConsole.exe` / `CloseFAH.exe` / `DIPUS.xml` (ISABEL-3501).

---

## Auditoria-LOPDP-Endpoint.ps1 — 10 bloques (cumplimiento LOPDP)

> **Por que un script separado?** Para **no confundir resultados ni alcance**: `Diagnostico` = salud, `Auditoria-Autoarranque` = amenazas, `LOPDP` = evidencia normativa (Art.10 Seguridad y Art.38 Medidas tecnicas) para la Superintendencia. Cada audiencia recibe solo su reporte.

| # | Control LOPDP | Riesgo si falta | Fuente | Semaforo | Mitigacion en reporte |
|---|---------------|-----------------|--------|----------|----------------------|
| 1 | **Cifrado de disco (BitLocker)** | Robo de laptop contable → extraccion de disco = brecha grave | `Get-BitLockerVolume` fallback `Win32_EncryptableVolume` `root\CIMv2\Security\MicrosoftVolumeEncryption` (`ProtectionStatus`) | `bad` si `C:` Off | `Enable-BitLocker C: -RecoveryPasswordProtector` + backup AD, `manage-bde -status` |
| 2 | **Puertos en escucha** | RDP 3389/SMB 445 expuestos → fuerza bruta / ransomware lateral | `Get-NetTCPConnection -State Listen` (fallback `netstat`) filtro `0.0.0.0/::` + `riskPorts @(3389,445,135,21,22,23,80,443,5985,5986)` | `bad` por cada puerto expuesto | `Set-NetFirewallRule -DisplayName "Remote Desktop*" -Enabled False` o VPN |
| 3 | **Firewall** | Perfiles off por usuario/malware → sin filtro SMB/RDP | `Get-NetFirewallProfile` Domain/Private/Public `Enabled`/`DefaultInboundAction` | `bad` si perfil off | `Set-NetFirewallProfile -Enabled True -DefaultInboundAction Block` via GPO |
| 4 | **Antivirus** | Proteccion off para pirateria → sin deteccion | `Get-MpComputerStatus` `AMServiceEnabled`/`RealTimeProtectionEnabled`/`AntivirusSignatureLastUpdated` fallback `root/SecurityCenter2` | `bad` si off o firmas >7 dias | `Update-MpSignature` + Tamper Protection |
| 5 | **Admins locales** | Usuario finanzas como Admin → malware hereda privilegios | `Get-LocalGroupMember -SID S-1-5-32-544` (idioma-indep.) fallback `net localgroup` | `warn` 3 cuentas, `bad` >3 | `Remove-LocalGroupMember`, LAPS, max 2 admins |

Resumen global `grid-summary` con 10 bloques (`totalBad` = core 5 + extra 5). Semaforo corrige falsos positivos: 445/135 con FW Block => warn, Domain Admins no cuentan para umbral, 5985/5986 => warn. Incluye `IsOneDrive` warning, params `-OutputPath`/`-NoOpen`/`-Days`, SHA256 + UTC en footer y exit code 1 si hay hallazgos (para RMM). Si no es Admin, `No verificado` en vez de falso OK.

---

## Auditoria-Office-Clipboard.ps1 — 12 bloques (Office/portapapeles)

Corrige el snippet original (espacios faltantes `foreach ($path in $paths)`, `Get-ItemProperty -Path $_.PSPath`, `-contains`, `Get-WinEvent -FilterHashtable $filter`, `try/catch` en hashtable).

| # | Bloque | Fuente | Que detecta | Hallazgo |
|---|--------|--------|-------------|----------|
| 1 | Office instalado | `HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration` + `Office16\EXCEL.EXE` VersionInfo / fallback MSI | Version `16.0.13801`, canal `Current/Monthly/SemiAnnual`, Producto `ProPlus2019Retail` | `warn` si canal desactualizado |
| 2 | COM Add-ins Excel | `HKCU/HKLM\...\Excel\Addins` (`LoadBehavior`) | `3=Activo inicio`, `2=Desactivado`, `0=Desconectado` | `warn` si `3` + cuelgue |
| 3 | Resiliency / DisabledItems | `HKCU\...\Excel\Resiliency\DisabledItems`, `CrashingAddinList` | Excel ya deshabilito Add-in tras cuelgue | `bad` si hay entradas |
| 4 | Aceleracion grafica | `HKCU\...\Common\Graphics\DisableHardwareAcceleration` + GPO | `1=deshabilitada`, `0=activa` | `warn` si GPO fuerza off |
| 5 | XLSTART / STARTUP | `%APPDATA%\Microsoft\Excel\XLSTART`, `Word\STARTUP`, `PERSONAL.XLSB` | `.xlam/.xla/.dotm` auto-carga | `bad` si `PERSONAL.XLSB` corrupto |
| 6 | Interceptores portapapeles | `Get-Process` vs 34 nombres (`PowerToys`, `Ditto`, `ShareX`, `Grammarly`, `DeepL`, `RdpClip`...) | Proceso roba clipboard | `bad` si 1+ detectado |
| 7 | Salud portapapeles | Win32 `OpenClipboard`/`GetClipboardSequenceNumber`/`GetClipboardOwner` + `Get-Clipboard` + `HKCU\Software\Microsoft\Clipboard` (Historial) | `CanOpen=bloqueado`, Owner PID, formatos, preview | `bad` si bloqueado |
| 8 | Registro Excel | `...\Excel\Options`, `Security\ProtectedView` | `DDEAllowed`, `ProtectedView` | info |
| 9 | Procesos Excel | `Get-Process EXCEL` (`Responding`, `CPU`, `RAM`, `Handles`) | `No responde` = colgado | `bad` si colgado |
| 10 | Eventos Hang/Crash | `Get-WinEvent` Application `1000/1001/1002` ultimos 14 dias filtro `excel.exe` | Hang (1002) / Crash (1000) | `bad` si hay |
| 11 | Reinicio pendiente | `CBS RebootPending`, `WU RebootRequired`, `PendingFileRenameOperations` | Reboot post-update deja clipboard inestable | `bad` si pendiente |
| 12 | Recomendaciones | Recuadro diagnostico rapido | Orden: interceptores -> `excel /safe` -> Gfx -> XLSTART -> Monitor | - |

Incluye `Invoke-OfficeAudit -AsJson` y modo modulo `. .\Auditoria-Office-Clipboard.ps1; Get-ExcelComAddins`.

---

## Monitor-Portapapeles.ps1 — tiempo real

Vigila polling `GetClipboardSequenceNumber` + `GetClipboardOwner` -> PID/Name (`user32.dll`) y `Get-Clipboard` preview/hash. Alerta si contenido sobreescrito en `<1.5s` por proceso distinto (patron Ditto/PowerToys/RdpClip), pitido + `<<< ALERTA`.

| Parametro | Default | Detalle |
|-----------|---------|---------|
| `-IntervalMs` | `300` | Sondeo ms. `200` mas preciso |
| `-DurationSec` | `0` (infinito) | `60` para captura de 1 min |
| `-LogPath` | vacio | `C:\diag\clip.csv` guarda `Timestamp,Seq,OwnerPID,OwnerName,Format,Hash,Preview,DeltaMs,Suspicious` |
| `-MaxPreviewChars` | `120` | Trunca preview TSV (`|` como separador) |
| `-IncludeImageHash` | off | Hashea imagen PNG |

Requiere STA (`powershell -STA ...` si avisa `MTA`). Sin Admin.

---

## Reparar-Portapapeles.ps1 — reparacion

7 fixes reversibles, todos con `SupportsShouldProcess` (`-WhatIf`/`-Confirm`) y backup `.reg` en `%TEMP%\OfficeClipFix_*` (via `reg export`).

| Switch | Registro/Accion | Reversible |
|--------|-----------------|------------|
| `-VaciarClipboard` | `user32!EmptyClipboard` + `Set-Clipboard $null` + `cmd clip` + `Forms.Clear` | Si (solo vacia) |
| `-ReiniciarRdpClip` | `Stop-Process rdpclip` + `Start-Process System32\rdpclip.exe` | Si |
| `-CerrarInterceptores` | `Stop-Process` 26 nombres conocidos | Si (reabrir app) |
| `-FixHistorial` | `HKCU\Software\Microsoft\Clipboard\EnableClipboardHistory=0` | Si (import .reg) |
| `-DeshabilitarGfx` | `HKCU\...\Common\Graphics\DisableHardwareAcceleration=1` | Si (poner `0` o borrar) |
| `-ReiniciarExcel` | `GetActiveComObject Excel.Application.CutCopyMode=$false` + mata solo `Responding=false` (con `-Force` mata todos) | Si |
| `-FixAddins` | `HKCU/HKLM\...\Excel\Addins\<Name>\LoadBehavior 3->2` (pregunta uno a uno, `-Force` auto) | Si (poner `3`) |
| `-All` | Activa 1-6 (`FixAddins` solo con `-Force`) | - |
| `-RepararOffice` | `OfficeC2RClient.exe /update user` | - |

`HKCU` no requiere Admin; `HKLM\...\Addins` si requiere Admin (sale `Acceso denegado` sin romper resto).

---

## Puntos ciegos cubiertos

Los 6 vectores que identificaste ya estan en `Auditoria-Autoarranque.ps1:5-10` (~linea 230/280/320/360/400/440), todos con `try/catch`, `HtmlEncode` y `badge`:
1. WMI `root/subscription`, 2. Exclusiones Defender, 3. `Get-NetTCPConnection` Stratum, 4. `Default\Extensions`, 5. `StartupApproved` byte 0, 6. `IFEO`/`AppInit`.

---

## Requisitos y compatibilidad

| Requisito | Detalle |
|-----------|---------|
| **SO** | Windows 10 21H2+ / Windows 11 (todas las ediciones). No Linux/macOS |
| **PowerShell** | 5.1 (Desktop, incluido) y 7+ (Core). Sin `??`, ternarios ni `utf8NoBOM` sin fallback. Verificado `Parser.ParseFile` = 0 errores (6 scripts) |
| **Permisos** | Mayoria sin Admin. Requieren Admin: `Get-WinEvent` (Visor), `root/subscription`, `Get-MpPreference`, `HKLM\StartupApproved`, `Get-BitLockerVolume`, `Get-NetFirewallProfile`, `Get-LocalGroupMember`, `HKLM\...\Excel\Addins` (escritura). Sin Admin se muestra `text-muted`/`No verificado`/`Acceso denegado`. Office/Clipboard/Monitor/Reparar (HKCU, vaciar clipboard, rdpclip, CutCopyMode) funcionan sin Admin |
| **Red** | Offline salvo `Test-Connection` y `winget` (opcionales) |
| **Codificacion** | `.ps1` ASCII puro. HTML `UTF-8` con BOM via `WriteAllText` + `meta charset` |

---

## Uso rapido

```powershell
# Desbloquear si viene de USB/otra PC (MOTW)
Unblock-File -Path .\Diagnostico-PC-HTML.ps1
Unblock-File -Path .\Auditoria-Autoarranque.ps1
Unblock-File -Path .\Auditoria-LOPDP-Endpoint.ps1
Unblock-File -Path .\Auditoria-Office-Clipboard.ps1
Unblock-File -Path .\Monitor-Portapapeles.ps1
Unblock-File -Path .\Reparar-Portapapeles.ps1

# Salud (cualquier usuario)
powershell -ExecutionPolicy Bypass -File .\Diagnostico-PC-HTML.ps1

# Caza de persistencia (cualquier usuario, mejor Admin)
powershell -ExecutionPolicy Bypass -File .\Auditoria-Autoarranque.ps1

# Cumplimiento LOPDP (requiere Admin para BitLocker/Firewall/Admins)
powershell -ExecutionPolicy Bypass -File .\Auditoria-LOPDP-Endpoint.ps1

# Office / Portapapeles (no requiere Admin)
powershell -ExecutionPolicy Bypass -File .\Auditoria-Office-Clipboard.ps1
powershell -ExecutionPolicy Bypass -File .\Auditoria-Office-Clipboard.ps1 -Days 7 -NoOpen -OutputPath C:\diag\office.html
# JSON / modulo
powershell -ExecutionPolicy Bypass -Command ".\Auditoria-Office-Clipboard.ps1 -AsJson -JsonPath C:\diag\office.json"
powershell -ExecutionPolicy Bypass -Command ". .\Auditoria-Office-Clipboard.ps1; Get-ExcelComAddins | Format-Table"

# Monitor tiempo real - dejar corriendo y luego copiar en Excel
powershell -STA -ExecutionPolicy Bypass -File .\Monitor-Portapapeles.ps1
powershell -STA -ExecutionPolicy Bypass -File .\Monitor-Portapapeles.ps1 -IntervalMs 200 -DurationSec 60 -LogPath C:\diag\clip.csv

# Reparar portapapeles - preview y luego fix
powershell -ExecutionPolicy Bypass -File .\Reparar-Portapapeles.ps1 -All -WhatIf
powershell -ExecutionPolicy Bypass -File .\Reparar-Portapapeles.ps1 -All
powershell -ExecutionPolicy Bypass -File .\Reparar-Portapapeles.ps1 -All -Force  # incluye FixAddins auto
powershell -ExecutionPolicy Bypass -File .\Reparar-Portapapeles.ps1 -VaciarClipboard -ReiniciarRdpClip -FixHistorial

# PowerShell 7
pwsh -ExecutionPolicy Bypass -File .\Auditoria-Office-Clipboard.ps1
```

Salidas `Auditoria-Office` en `Desktop\Auditoria_Office_<HOST>_<fecha>.html` + `Start-Process` automatico (o `-NoOpen`). `Monitor` en consola + CSV. `Reparar` en consola + backup `.reg` en `%TEMP%\OfficeClipFix_*`. HTML sin recursos externos, abre en Edge/Chrome/Firefox y en `file://`.
Flujo recomendado Office: `Auditoria-Office-Clipboard` -> `Monitor-Portapapeles` (copia en Excel) -> `Reparar-Portapapeles -All` -> re-probar copia.

### Ejecucion sin descargar (curl / irm) — one-liner en memoria

No requiere clonar ni guardar `.ps1`. Usa `Invoke-RestMethod` (`irm`) + `Invoke-Expression` (`iex`) contra `raw.githubusercontent.com` (TLS 1.2).

```powershell
# Auditoria Office (HTML en Escritorio)
powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; iex (irm https://raw.githubusercontent.com/xeland314/WindowsDiagnosis/main/Auditoria-Office-Clipboard.ps1)"
# con params (ej. 7 dias, sin abrir)
powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((irm https://raw.githubusercontent.com/xeland314/WindowsDiagnosis/main/Auditoria-Office-Clipboard.ps1))) -Days 7 -NoOpen"

# Monitor tiempo real (STA obligatorio)
powershell -STA -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; iex (irm https://raw.githubusercontent.com/xeland314/WindowsDiagnosis/main/Monitor-Portapapeles.ps1)"
powershell -STA -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((irm https://raw.githubusercontent.com/xeland314/WindowsDiagnosis/main/Monitor-Portapapeles.ps1))) -IntervalMs 200 -DurationSec 60 -LogPath C:\diag\clip.csv"

# Reparar (preview luego fix real)
powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((irm https://raw.githubusercontent.com/xeland314/WindowsDiagnosis/main/Reparar-Portapapeles.ps1))) -All -WhatIf"
powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((irm https://raw.githubusercontent.com/xeland314/WindowsDiagnosis/main/Reparar-Portapapeles.ps1))) -All"
powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((irm https://raw.githubusercontent.com/xeland314/WindowsDiagnosis/main/Reparar-Portapapeles.ps1))) -VaciarClipboard -ReiniciarRdpClip -FixHistorial"

# Alternativa curl (alias de Invoke-WebRequest en PS)
powershell -ExecutionPolicy Bypass -Command "iex (curl -UseBasicParsing https://raw.githubusercontent.com/xeland314/WindowsDiagnosis/main/Auditoria-Office-Clipboard.ps1).Content"
```

### Alternativa para Kaspersky / AV (evita fileless `iex`, menos deteccion)

`iex (irm ...)` es patron fileless y Kaspersky lo marca `HEUR:Trojan.PowerShell.Generic`. Para AV usa descarga a archivo temporal + `-File`:

```powershell
curl.exe -L -o $env:TEMP\audit.ps1 https://raw.githubusercontent.com/xeland314/WindowsDiagnosis/main/Auditoria-Office-Clipboard.ps1
powershell -ExecutionPolicy Bypass -File $env:TEMP\audit.ps1
# con params
curl.exe -L -o $env:TEMP\audit.ps1 https://raw.githubusercontent.com/xeland314/WindowsDiagnosis/main/Auditoria-Office-Clipboard.ps1
powershell -ExecutionPolicy Bypass -File $env:TEMP\audit.ps1 -Days 7 -NoOpen
# Monitor y Reparar igual
curl.exe -L -o $env:TEMP\mon.ps1 https://raw.githubusercontent.com/xeland314/WindowsDiagnosis/main/Monitor-Portapapeles.ps1
powershell -STA -ExecutionPolicy Bypass -File $env:TEMP\mon.ps1 -IntervalMs 200
curl.exe -L -o $env:TEMP\fix.ps1 https://raw.githubusercontent.com/xeland314/WindowsDiagnosis/main/Reparar-Portapapeles.ps1
powershell -ExecutionPolicy Bypass -File $env:TEMP\fix.ps1 -All -WhatIf
```

Borra tras uso: `Remove-Item $env:TEMP\audit.ps1 -Force`.

> Nota: `Bypass -Scope Process` no persiste y no requiere Admin salvo `MachinePolicy` via GPO. En `ConstrainedLanguage` el one-liner falla — usa archivo local y firma.

---

## Estructura del repo y builders

```
WindowsDiagnosis/
  Diagnostico-PC-HTML.ps1          # 888 lineas, ASCII
  Auditoria-Autoarranque.ps1       # 1262 lineas, ASCII
  Auditoria-LOPDP-Endpoint.ps1     # 1026 lineas, ASCII
  Auditoria-Office-Clipboard.ps1   # ~1000 lineas, ASCII (12 bloques Office/clipboard)
  Monitor-Portapapeles.ps1         # ~260 lineas, ASCII (tiempo real)
  Reparar-Portapapeles.ps1         # ~380 lineas, ASCII (7 fixes -WhatIf)
  tools/
    build_diagnostico.py           # genera Diagnostico-PC-HTML.ps1
    build_auditoria.py             # genera Auditoria-Autoarranque.ps1
    build_lopdp.py                 # genera Auditoria-LOPDP-Endpoint.ps1
  README.md
```

> Se mantiene como **scripts separados** por decision actual — portables por USB con `Bypass`. No hay refactor a modulo `psm1` por ahora; el patron `tools/build_*.py` permite mantener repo modular en Python y entregar monolitos ASCII.

---

## FAQ

**¿Por que sin tildes?** PS 5.1 lee `.ps1` como ANSI si no tiene BOM; los acentos salen `�` y rompen `Write-Host` segun codepage. ASCII garantiza copia tal cual desde USB.

**¿El HTML sigue siendo UTF-8?** Si. Declara `charset=UTF-8` + `http-equiv` y se escribe `UTF8` con BOM; el contenido solo evita diacriticos asi que no hay mojibake.

**¿Reconstruyo el .ps1 desde Python?**
```powershell
python tools/build_diagnostico.py
python tools/build_auditoria.py
python tools/build_lopdp.py
```

**¿Funciona sin internet / sin winget / sin Defender / sin BitLocker?** Si. Cada bloque tiene fallback (`SecurityCenter2`, `netstat`, `net localgroup`, `Win32_NetworkAdapter`) y muestra `text-muted` si la fuente no existe.

**¿Puedo anadir logo?** Si: `<img src="data:image/png;base64,...">` en `.header` del `$htmlContent`.

---

*WindowsDiagnosis — 2026-09-17. Verificado PS 5.1 y 7+ en Windows 10/11. 6 scripts, Parser 0 errores. Builders en `tools/`.*
