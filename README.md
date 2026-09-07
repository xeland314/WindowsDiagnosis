# WindowsDiagnosis — Diagnostico, Auditoria y Cumplimiento LOPDP para Windows

> Tres scripts **PowerShell sin dependencias** que generan reportes **HTML portables** (CSS inline, sin CDN/JS) para soporte tecnico, caza de persistencia y auditoria de cumplimiento **LOPDP Art. 10 y 38** (Ecuador). Compatibles **Windows 10 21H2+ / Windows 11** con **PowerShell 5.1** (Desktop) y **7+** (Core).

> **Sin tildes en codigo ni en HTML:** todo ASCII para que PowerShell 5.1 —que lee `.ps1` como ANSI si no tiene BOM— no rompa `Write-Host` ni comentarios al copiar desde USB. El HTML sigue declarando `UTF-8` (`<meta charset="UTF-8">` + `http-equiv`) y se escribe con `[System.IO.File]::WriteAllText(..., UTF8)` (con BOM) para Notepad/navegador, pero el contenido evita diacriticos y evita mojibake en `file://`.

---

## Indice

- [Scripts](#scripts)
- [Diagnostico-PC-HTML.ps1 — 12 bloques](#diagnostico-pc-htmlps1---12-bloques)
- [Auditoria-Autoarranque.ps1 — 10 bloques](#auditoria-autoarranqueps1---10-bloques-persistencia-y-caza-de-amenazas)
- [Auditoria-LOPDP-Endpoint.ps1 — 5 bloques](#auditoria-lopdp-endpointps1---5-bloques-cumplimiento-lopdp)
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
| `Auditoria-LOPDP-Endpoint.ps1` | **Cumplimiento LOPDP Art.10/38** — controles minimos de endpoint con datos personales | `Desktop\Auditoria_LOPDP_<HOST>_<fecha>.html` | Auditoria legal, visita Superintendencia, rodo de laptops contables |

Builders (solo desarrollo, no necesarios para ejecutar):

| Builder | Genera |
|---------|--------|
| `tools/build_diagnostico.py` | `Diagnostico-PC-HTML.ps1` (780 lineas, ASCII) |
| `tools/build_auditoria.py` | `Auditoria-Autoarranque.ps1` (719 lineas, ASCII) |
| `tools/build_lopdp.py` | `Auditoria-LOPDP-Endpoint.ps1` (477 lineas, ASCII) |

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

## Auditoria-LOPDP-Endpoint.ps1 — 5 bloques (cumplimiento LOPDP)

> **Por que un script separado?** Para **no confundir resultados ni alcance**: `Diagnostico` = salud, `Auditoria-Autoarranque` = amenazas, `LOPDP` = evidencia normativa (Art.10 Seguridad y Art.38 Medidas tecnicas) para la Superintendencia. Cada audiencia recibe solo su reporte.

| # | Control LOPDP | Riesgo si falta | Fuente | Semaforo | Mitigacion en reporte |
|---|---------------|-----------------|--------|----------|----------------------|
| 1 | **Cifrado de disco (BitLocker)** | Robo de laptop contable → extraccion de disco = brecha grave | `Get-BitLockerVolume` fallback `Win32_EncryptableVolume` `root\CIMv2\Security\MicrosoftVolumeEncryption` (`ProtectionStatus`) | `bad` si `C:` Off | `Enable-BitLocker C: -RecoveryPasswordProtector` + backup AD, `manage-bde -status` |
| 2 | **Puertos en escucha** | RDP 3389/SMB 445 expuestos → fuerza bruta / ransomware lateral | `Get-NetTCPConnection -State Listen` (fallback `netstat`) filtro `0.0.0.0/::` + `riskPorts @(3389,445,135,21,22,23,80,443,5985,5986)` | `bad` por cada puerto expuesto | `Set-NetFirewallRule -DisplayName "Remote Desktop*" -Enabled False` o VPN |
| 3 | **Firewall** | Perfiles off por usuario/malware → sin filtro SMB/RDP | `Get-NetFirewallProfile` Domain/Private/Public `Enabled`/`DefaultInboundAction` | `bad` si perfil off | `Set-NetFirewallProfile -Enabled True -DefaultInboundAction Block` via GPO |
| 4 | **Antivirus** | Proteccion off para pirateria → sin deteccion | `Get-MpComputerStatus` `AMServiceEnabled`/`RealTimeProtectionEnabled`/`AntivirusSignatureLastUpdated` fallback `root/SecurityCenter2` | `bad` si off o firmas >7 dias | `Update-MpSignature` + Tamper Protection |
| 5 | **Admins locales** | Usuario finanzas como Admin → malware hereda privilegios | `Get-LocalGroupMember -SID S-1-5-32-544` (idioma-indep.) fallback `net localgroup` | `warn` 3 cuentas, `bad` >3 | `Remove-LocalGroupMember`, LAPS, max 2 admins |

Resumen global `grid-summary` con 5 cards + badge `ok/warn/bad` (`totalBad` suman los 5 controles). Si no es sesion Admin, muestra `No verificado` en vez de falso OK.

---

## Puntos ciegos cubiertos

Los 6 vectores que identificaste ya estan en `Auditoria-Autoarranque.ps1:5-10` (~linea 230/280/320/360/400/440), todos con `try/catch`, `HtmlEncode` y `badge`:
1. WMI `root/subscription`, 2. Exclusiones Defender, 3. `Get-NetTCPConnection` Stratum, 4. `Default\Extensions`, 5. `StartupApproved` byte 0, 6. `IFEO`/`AppInit`.

---

## Requisitos y compatibilidad

| Requisito | Detalle |
|-----------|---------|
| **SO** | Windows 10 21H2+ / Windows 11 (todas las ediciones). No Linux/macOS |
| **PowerShell** | 5.1 (Desktop, incluido) y 7+ (Core). Sin `??`, ternarios ni `utf8NoBOM` sin fallback. Verificado `Parser.ParseFile` = 0 errores |
| **Permisos** | Mayoria sin Admin. Requieren Admin: `Get-WinEvent` (Visor), `root/subscription`, `Get-MpPreference`, `HKLM\StartupApproved`, `Get-BitLockerVolume`, `Get-NetFirewallProfile`, `Get-LocalGroupMember`. Sin Admin se muestra `text-muted`/`No verificado` |
| **Red** | Offline salvo `Test-Connection` y `winget` (opcionales) |
| **Codificacion** | `.ps1` ASCII puro. HTML `UTF-8` con BOM via `WriteAllText` + `meta charset` |

---

## Uso rapido

```powershell
# Desbloquear si viene de USB/otra PC (MOTW)
Unblock-File -Path .\Diagnostico-PC-HTML.ps1
Unblock-File -Path .\Auditoria-Autoarranque.ps1
Unblock-File -Path .\Auditoria-LOPDP-Endpoint.ps1

# Salud (cualquier usuario)
powershell -ExecutionPolicy Bypass -File .\Diagnostico-PC-HTML.ps1

# Caza de persistencia (cualquier usuario, mejor Admin)
powershell -ExecutionPolicy Bypass -File .\Auditoria-Autoarranque.ps1

# Cumplimiento LOPDP (requiere Admin para BitLocker/Firewall/Admins)
powershell -ExecutionPolicy Bypass -File .\Auditoria-LOPDP-Endpoint.ps1

# PowerShell 7
pwsh -ExecutionPolicy Bypass -File .\Auditoria-LOPDP-Endpoint.ps1
```

Salidas en `Desktop\*.html` + `Start-Process` automatico. HTML sin recursos externos, abre en Edge/Chrome/Firefox y en `file://`.

---

## Estructura del repo y builders

```
WindowsDiagnosis/
  Diagnostico-PC-HTML.ps1          # 780 lineas, ASCII
  Auditoria-Autoarranque.ps1       # 719 lineas, ASCII
  Auditoria-LOPDP-Endpoint.ps1     # 477 lineas, ASCII
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

*WindowsDiagnosis — 2026-09-07. Verificado PS 5.1 y 7+ en Windows 10/11. Builders en `tools/`.*
