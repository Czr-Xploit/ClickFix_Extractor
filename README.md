# ClickFix Toolkit — draw.io Electron RAT

[![TLP:WHITE](https://img.shields.io/badge/TLP-WHITE-lightgrey?style=flat-square)](https://www.cisa.gov/tlp)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)](https://python.org)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?style=flat-square)]()
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

**3 scripts para analizar la campaña ClickFix que entrega un RAT disfrazado de draw.io v19.0.3.**

> TLP:WHITE — Uso exclusivo para investigación defensiva y respuesta a incidentes.

---

## ¿Qué hace esta campaña?

```
1. Página falsa de Cloudflare pide Win+R → Ctrl+V → Enter
2. PowerShell descarga e instala draw.io troyanizado desde ccudmcx[.]xyz
3. El falso draw.io envía hostname + usuario al atacante cada 65 segundos
4. El atacante puede ejecutar código o instalar más malware remotamente
```

---

## Scripts incluidos

| Script | Para qué sirve |
|---|---|
| `clickfix_deobfuscate.py` | Decodifica los 1.015 strings ofuscados de `electron.js` (RC4 + Base64 custom) |
| `clickfix_ioc_extractor.py` | Extrae IOCs del resultado anterior y genera bundle STIX 2.1 |
| `clickfix_infection_check.ps1` | Verifica en Windows si ya fuiste infectado (8 comprobaciones) |

---

## Uso rápido

```bash
# 1. Desobfuscar electron.js del malware
python3 clickfix_deobfuscate.py electron.js

# 2. Extraer IOCs del resultado (+ hashes de muestras + STIX)
python3 clickfix_ioc_extractor.py \
    --strings deobfuscated_strings.json \
    --samples ./samples/ \
    --stix

# 3. Verificar si un equipo Windows está infectado
powershell -ExecutionPolicy Bypass -File clickfix_infection_check.ps1
```

---

## IOCs confirmados

```
DOMINIOS (bloquear en DNS/proxy):
  dominio[.]com          ← sitio de entrega (CAPTCHA falso)
  ccudmcx[.]xyz/u           ← host del stager PowerShell
  ccudmcx[.]xyz/update.zip    ← host del dropper ZIP
  chimefusion[.]com      ← C2 activo (beacon cada 65s)

ARCHIVOS (si existen → infectado):
  %LOCALAPPDATA%\UpdateApp\draw.io.exe
  %APPDATA%\setup.txt
  %LOCALAPPDATA%\Microsoft\Cache\demo.log
  %TEMP%\runner.ps1

REGISTRO:
  HKCU\...\CurrentVersion\Run → draw.io = ...UpdateApp\draw.io.exe
```

---

## Documentación completa

El análisis técnico profundo está en [`/zerotrustoffsec.com/blog/`](https://zerotrustoffsec.com/blog/).

---

## Aviso legal

Herramientas para uso defensivo. Requiere autorización sobre los sistemas analizados.
