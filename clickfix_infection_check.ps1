<#
.SYNOPSIS
    Verifica si un equipo Windows está infectado por el ClickFix draw.io Electron RAT.

.DESCRIPTION
    Realiza 8 comprobaciones en el sistema local para detectar indicadores de
    compromiso de la campaña ClickFix que entrega un RAT disfrazado de draw.io v19.0.3.

    La campaña funciona así:
      1. Página falsa de Cloudflare convence al usuario de ejecutar Win+R → pegar → Enter
      2. PowerShell instala silenciosamente draw.io troyanizado desde ccudmcx.xyz
      3. El falso draw.io envía hostname + usuario a chimefusion.com cada 65 segundos
      4. El atacante puede ejecutar código o instalar más malware de forma remota

    Ejecutar como el usuario sospechoso (no necesita privilegios de administrador).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File clickfix_infection_check.ps1

.NOTES
    TLP:WHITE | https://github.com/tu-handle/clickfix-drawio-electron-rat
    Campaña: fepafut.com → cudmcx.xyz → ccudmcx.xyz → chimefusion.com
#>

# ─── Configuración ────────────────────────────────────────────────────────────

$ErrorActionPreference = "SilentlyContinue"

# Dominios C2 conocidos de esta campaña
$C2_DOMAINS = @(
    "chimefusion.com",   # C2 principal — recibe beacons cada 65s
    "cudmcx.xyz",        # Host del stager PowerShell
    "ccudmcx.xyz",       # Host del dropper ZIP
    "fepafut.com"        # Sitio de entrega (CAPTCHA falso)
)

# Rutas de artefactos en disco (usando variables de entorno del usuario actual)
$PATHS = @{
    "Binario RAT"         = "$env:LOCALAPPDATA\UpdateApp\draw.io.exe"
    "UUID del dispositivo"= "$env:APPDATA\setup.txt"
    "Log señuelo Etapa 2" = "$env:LOCALAPPDATA\Microsoft\Cache\demo.log"
    "Dropper PS1"         = "$env:TEMP\runner.ps1"
    "ZIP temporal"        = "$env:TEMP\update26.zip"
}

# Variables de resultado
$infectado = $false
$hallazgos = [System.Collections.Generic.List[string]]::new()
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"


# ─── Funciones auxiliares ─────────────────────────────────────────────────────

function Write-Check {
    param([string]$titulo, [bool]$encontrado, [string]$detalle = "")
    if ($encontrado) {
        Write-Host "  [INFECTADO] $titulo" -ForegroundColor Red
        if ($detalle) { Write-Host "              $detalle" -ForegroundColor DarkRed }
    } else {
        Write-Host "  [LIMPIO]    $titulo" -ForegroundColor Green
    }
}

function Write-Section {
    param([string]$titulo)
    Write-Host "`n$('─' * 50)" -ForegroundColor Cyan
    Write-Host "  $titulo" -ForegroundColor Cyan
    Write-Host "$('─' * 50)" -ForegroundColor Cyan
}


# ─── Encabezado ───────────────────────────────────────────────────────────────

Write-Host "`n$('=' * 60)" -ForegroundColor Cyan
Write-Host "  ClickFix Electron RAT — Verificación de Infección" -ForegroundColor Cyan
Write-Host "  Campaña: fepafut.com / chimefusion.com" -ForegroundColor DarkCyan
Write-Host "  Fecha:   $timestamp" -ForegroundColor DarkCyan
Write-Host "  Host:    $env:COMPUTERNAME | Usuario: $env:USERNAME" -ForegroundColor DarkCyan
Write-Host "$('=' * 60)" -ForegroundColor Cyan


# ─── CHECK 1: Binario del RAT ─────────────────────────────────────────────────
# draw.io legítimo se instala en Program Files o AppData\Local\Programs\draw.io\
# El RAT siempre se instala en AppData\Local\UpdateApp\ — ruta única de la campaña

Write-Section "CHECK 1 — Binario del RAT en disco"

$ratPath = "$env:LOCALAPPDATA\UpdateApp\draw.io.exe"
if (Test-Path $ratPath) {
    $fileInfo = Get-Item $ratPath
    $hash     = (Get-FileHash $ratPath -Algorithm SHA256).Hash
    $size     = $fileInfo.Length
    $created  = $fileInfo.CreationTime

    Write-Check "draw.io.exe en UpdateApp\" $true
    Write-Host "              Ruta:     $ratPath" -ForegroundColor DarkRed
    Write-Host "              SHA256:   $hash" -ForegroundColor DarkRed
    Write-Host "              Tamaño:   $("{0:N0}" -f $size) bytes" -ForegroundColor DarkRed
    Write-Host "              Creado:   $created" -ForegroundColor DarkRed
    Write-Host "              ⚠️  draw.io LEGÍTIMO nunca se instala en UpdateApp" -ForegroundColor Yellow

    $infectado = $true
    $hallazgos.Add("RAT binario: $ratPath (SHA256: $hash)")
} else {
    Write-Check "draw.io.exe en UpdateApp\" $false
}


# ─── CHECK 2: UUID del dispositivo (fue enviado al C2) ───────────────────────
# El RAT genera un UUID de 8 caracteres y lo guarda en setup.txt
# Este UUID es enviado al C2 en cada beacon — si existe, el C2 ya conoce este equipo

Write-Section "CHECK 2 — UUID del dispositivo (registrado en C2)"

$uuidPath = "$env:APPDATA\setup.txt"
if (Test-Path $uuidPath) {
    $uuid = Get-Content $uuidPath -Raw -EA SilentlyContinue
    $uuid = if ($uuid) { $uuid.Trim() } else { "vacío" }

    Write-Check "setup.txt encontrado" $true
    Write-Host "              Ruta:  $uuidPath" -ForegroundColor DarkRed
    Write-Host "              UUID:  $uuid" -ForegroundColor DarkRed
    Write-Host "              ⚠️  Este ID fue enviado a chimefusion.com en cada beacon" -ForegroundColor Yellow

    # Estimar fecha de infección y número de beacons enviados
    $fileDate = (Get-Item $uuidPath).CreationTime
    $segundos = ([datetime]::Now - $fileDate).TotalSeconds
    $beacons  = [math]::Floor($segundos / 65)
    Write-Host "              Fecha de infección estimada: $fileDate" -ForegroundColor DarkYellow
    Write-Host "              Beacons enviados estimados:  $beacons (c/65s desde la infección)" -ForegroundColor DarkYellow

    $infectado = $true
    $hallazgos.Add("UUID del dispositivo: $uuid (infectado desde: $fileDate)")
} else {
    Write-Check "setup.txt" $false
}


# ─── CHECK 3: Log señuelo de la Etapa 2 ──────────────────────────────────────
# El stager PS1 crea este log con operaciones benignas para parecer legítimo
# Si existe, confirma que la Etapa 2 se ejecutó (aunque el RAT ya no esté)

Write-Section "CHECK 3 — Log señuelo de la Etapa 2"

$logPath = "$env:LOCALAPPDATA\Microsoft\Cache\demo.log"
if (Test-Path $logPath) {
    $lineas = (Get-Content $logPath -EA SilentlyContinue | Measure-Object -Line).Lines
    Write-Check "demo.log encontrado (Etapa 2 ejecutada)" $true
    Write-Host "              Ruta:   $logPath" -ForegroundColor DarkRed
    Write-Host "              Líneas: $lineas" -ForegroundColor DarkRed
    Write-Host "              ℹ️  Este log es benigno pero confirma que el dropper corrió" -ForegroundColor Yellow

    # El log contiene texto como: "[12:34:56] Script completed successfully"
    # Es inofensivo por sí mismo pero es evidencia forense valiosa
    $infectado = $true
    $hallazgos.Add("Log señuelo presente: $logPath ($lineas líneas)")
} else {
    Write-Check "demo.log" $false
}


# ─── CHECK 4: Persistencia en el registro ────────────────────────────────────
# El RAT usa Electron's setLoginItemSettings() que agrega una entrada en HKCU\Run
# Esto hace que draw.io.exe (el RAT) se ejecute automáticamente en cada inicio de sesión

Write-Section "CHECK 4 — Persistencia en registro HKCU\Run"

$runKey  = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$runProps = Get-ItemProperty $runKey -EA SilentlyContinue

$autorunMalicioso = $false
if ($runProps) {
    $runProps.PSObject.Properties | Where-Object {
        $_.Value -match "draw\.io|UpdateApp"
    } | ForEach-Object {
        Write-Check "Entrada de autorun maliciosa" $true
        Write-Host "              Nombre: $($_.Name)" -ForegroundColor DarkRed
        Write-Host "              Valor:  $($_.Value)" -ForegroundColor DarkRed
        Write-Host "              ⚠️  Se ejecuta en cada inicio de sesión de $env:USERNAME" -ForegroundColor Yellow

        $infectado       = $true
        $autorunMalicioso = $true
        $hallazgos.Add("Autorun: HKCU\Run\$($_.Name) = $($_.Value)")
    }
}
if (-not $autorunMalicioso) {
    Write-Check "Entradas HKCU\Run (sin sospechosos)" $false
}


# ─── CHECK 5: Conexiones de red activas al C2 ────────────────────────────────
# Si el RAT está corriendo, debería haber conexiones TCP activas a chimefusion.com
# Este check intenta resolver los nombres de las conexiones establecidas

Write-Section "CHECK 5 — Conexiones TCP activas a dominios C2"

$conexionC2 = $false
Get-NetTCPConnection -State Established -EA SilentlyContinue | ForEach-Object {
    $conn = $_
    try {
        $hostname = [System.Net.Dns]::GetHostEntry($conn.RemoteAddress).HostName
        if ($C2_DOMAINS | Where-Object { $hostname -match $_ }) {
            Write-Check "Conexión activa al C2: $hostname" $true
            Write-Host "              IP remota: $($conn.RemoteAddress):$($conn.RemotePort)" -ForegroundColor DarkRed
            Write-Host "              PID local: $($conn.OwningProcess)" -ForegroundColor DarkRed

            $proceso = Get-Process -Id $conn.OwningProcess -EA SilentlyContinue
            if ($proceso) {
                Write-Host "              Proceso:  $($proceso.Name) ($($proceso.Path))" -ForegroundColor DarkRed
            }

            $infectado   = $true
            $conexionC2  = $true
            $hallazgos.Add("Conexión C2 activa: $hostname ($($conn.RemoteAddress))")
        }
    } catch {}
}
if (-not $conexionC2) {
    Write-Check "Sin conexiones activas a dominios C2" $false
}


# ─── CHECK 6: Procesos desde UpdateApp ───────────────────────────────────────
# Si draw.io.exe está corriendo desde AppData\UpdateApp, el RAT está activo en memoria

Write-Section "CHECK 6 — Procesos sospechosos en ejecución"

$procesosRAT = Get-Process -EA SilentlyContinue | Where-Object {
    $_.Path -like "*\UpdateApp\*" -or
    ($_.Name -like "*draw.io*" -and $_.Path -like "*\AppData\*")
}

if ($procesosRAT) {
    foreach ($proc in $procesosRAT) {
        Write-Check "RAT en memoria: $($proc.Name) (PID $($proc.Id))" $true
        Write-Host "              Ruta: $($proc.Path)" -ForegroundColor DarkRed
        Write-Host "              ⚠️  El RAT está activo — enviando beacons al C2 ahora" -ForegroundColor Yellow
        $infectado = $true
        $hallazgos.Add("Proceso RAT activo: $($proc.Name) PID:$($proc.Id) Path:$($proc.Path)")
    }
} else {
    Write-Check "Sin procesos desde UpdateApp" $false
}


# ─── CHECK 7: Directorios de drop del C2 en TEMP ─────────────────────────────
# Cuando el C2 envía binarios para ejecutar, los guarda en %TEMP%\<timestamp-13-digitos>\
# Estos directorios son evidencia de que el C2 ejecutó comandos en el equipo

Write-Section "CHECK 7 — Directorios de drop del C2 en TEMP"

$dropDirs = Get-ChildItem $env:TEMP -Directory -EA SilentlyContinue |
    Where-Object { $_.Name -match '^\d{13}$' }  # timestamp epoch en milisegundos

if ($dropDirs) {
    foreach ($dir in $dropDirs) {
        $contenido = (Get-ChildItem $dir.FullName -EA SilentlyContinue).Count
        Write-Check "Directorio de drop C2: $($dir.Name)" $true
        Write-Host "              Ruta:     $($dir.FullName)" -ForegroundColor DarkRed
        Write-Host "              Archivos: $contenido" -ForegroundColor DarkRed
        Write-Host "              ℹ️  El C2 ejecutó una tarea que dropeó archivos aquí" -ForegroundColor Yellow
        $hallazgos.Add("Directorio drop C2: $($dir.FullName) ($contenido archivos)")
    }
} else {
    Write-Check "Sin directorios de drop en TEMP" $false
}


# ─── CHECK 8: Artefactos del dropper ─────────────────────────────────────────
# El script runner.ps1 y el ZIP update26.zip son artefactos de la Etapa 2
# El ZIP se elimina automáticamente, pero runner.ps1 puede quedar

Write-Section "CHECK 8 — Artefactos del dropper en TEMP"

$artefactos = @("$env:TEMP\runner.ps1", "$env:TEMP\update26.zip")
$hayArtefactos = $false

foreach ($artefacto in $artefactos) {
    if (Test-Path $artefacto) {
        Write-Check "Artefacto del dropper: $(Split-Path $artefacto -Leaf)" $true
        Write-Host "              Ruta: $artefacto" -ForegroundColor DarkYellow
        $hayArtefactos = $true
        $hallazgos.Add("Artefacto dropper: $artefacto")
    }
}
if (-not $hayArtefactos) {
    Write-Check "Sin artefactos del dropper en TEMP" $false
}


# ─── RESULTADO FINAL ──────────────────────────────────────────────────────────

Write-Host "`n$('=' * 60)" -ForegroundColor Cyan

if ($infectado) {
    Write-Host "`n  ██████████████████████████████████" -ForegroundColor Red
    Write-Host "  ██   HOST INFECTADO               ██" -ForegroundColor Red
    Write-Host "  ██████████████████████████████████" -ForegroundColor Red

    Write-Host "`n  Hallazgos:" -ForegroundColor Red
    foreach ($h in $hallazgos) {
        Write-Host "    • $h" -ForegroundColor DarkRed
    }

    Write-Host "`n  ACCIONES INMEDIATAS REQUERIDAS:" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────────" -ForegroundColor Yellow
    Write-Host "  1. DESCONECTAR de la red ahora (cable o WiFi)" -ForegroundColor Yellow
    Write-Host "  2. NO apagar el equipo (se pierde evidencia en memoria)" -ForegroundColor Yellow
    Write-Host "  3. CONTACTAR al equipo de seguridad / SOC" -ForegroundColor Yellow
    Write-Host "  4. CAMBIAR contraseñas desde OTRO dispositivo" -ForegroundColor Yellow
    Write-Host "     → email, banco, trabajo, redes sociales" -ForegroundColor Yellow
    Write-Host "  5. ASUMIR compromiso de credenciales en este equipo" -ForegroundColor Yellow
    Write-Host "  6. REIMAGEN del sistema recomendada (C2 tenía eval())" -ForegroundColor Yellow

    Write-Host "`n  IOCs de esta infección:" -ForegroundColor DarkCyan
    Write-Host "  Dominios C2: chimefusion[.]com, cudmcx[.]xyz, ccudmcx[.]xyz" -ForegroundColor DarkCyan
    Write-Host "  Reporte:     https://github.com/tu-handle/clickfix-drawio-electron-rat" -ForegroundColor DarkCyan

} else {
    Write-Host "`n  ✓ Sin indicadores de ClickFix Electron RAT detectados" -ForegroundColor Green
    Write-Host "`n  Nota: Este script verifica solo los IOCs conocidos de la campaña" -ForegroundColor DarkCyan
    Write-Host "  fepafut.com / chimefusion.com. Otras variantes pueden usar" -ForegroundColor DarkCyan
    Write-Host "  diferentes rutas o dominios." -ForegroundColor DarkCyan
}

Write-Host "`n$('=' * 60)" -ForegroundColor Cyan


# ─── GUARDAR REPORTE JSON ─────────────────────────────────────────────────────

$reportPath = "$env:TEMP\clickfix_check_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"

$reporte = @{
    timestamp  = $timestamp
    hostname   = $env:COMPUTERNAME
    username   = $env:USERNAME
    infectado  = $infectado
    hallazgos  = $hallazgos.ToArray()
    iocs       = @{
        dominios_c2 = $C2_DOMAINS
        rutas       = $PATHS
    }
} | ConvertTo-Json -Depth 5

$reporte | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host "`n[+] Reporte guardado en: $reportPath" -ForegroundColor Cyan
Write-Host "    Compartir con el equipo de seguridad para análisis forense.`n" -ForegroundColor DarkCyan
