#!/usr/bin/env python3
"""
clickfix_ioc_extractor.py
=========================
Extrae IOCs del resultado de clickfix_deobfuscate.py y genera:
  - Reporte de IOCs en consola
  - Archivo JSON estructurado con todos los IOCs
  - Hashes SHA256/MD5 de archivos de muestras (opcional)
  - Bundle STIX 2.1 para subir a OTX/MISP/ThreatFox (opcional)

Uso:
    # Solo IOCs desde strings desobfuscados
    python3 clickfix_ioc_extractor.py --strings deobfuscated_strings.json

    # Con hashes de muestras
    python3 clickfix_ioc_extractor.py --strings deobfuscated_strings.json --samples ./muestras/

    # Con bundle STIX 2.1
    python3 clickfix_ioc_extractor.py --strings deobfuscated_strings.json --stix

    # Todo junto
    python3 clickfix_ioc_extractor.py \
        --strings deobfuscated_strings.json \
        --samples ./muestras/ \
        --stix \
        --output iocs_completos.json

Requiere para STIX:
    pip3 install stix2 --break-system-packages

TLP:WHITE | https://github.com/tu-handle/clickfix-drawio-electron-rat
"""

import re
import sys
import json
import uuid
import hashlib
import argparse
from pathlib import Path
from datetime import datetime, timezone


# ─── Dominios legítimos a ignorar ────────────────────────────────────────────
# Para evitar falsos positivos al extraer dominios de los strings desobfuscados
WHITELIST = {
    "diagrams.net",
    "github.com",
    "electron.org",
    "microsoft.com",
    "googleapis.com",
    "npmjs.com",
    "jquery.com",
    "cloudflare.com",
}


# ─── Extracción de IOCs ───────────────────────────────────────────────────────

def extract_network_iocs(decoded: dict) -> dict:
    """
    Extrae dominios, URLs e IPs de los strings desobfuscados.
    
    Filtra dominios de la whitelist para evitar falsos positivos
    (diagrams.net, github.com, etc. aparecen porque draw.io es legítimo).
    """
    domains: set[str] = set()
    urls: set[str] = set()
    ips: set[str] = set()

    url_re    = re.compile(r"https?://[^\s\"'<>]+")
    domain_re = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
    ip_re     = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    for val in decoded.values():
        # Extraer URLs completas
        for url in url_re.findall(val):
            host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
            if host not in WHITELIST and "." in host:
                urls.add(url)
                domains.add(host)

        # Extraer dominios individuales
        for domain in domain_re.findall(val):
            if domain not in WHITELIST and len(domain) > 5:
                domains.add(domain)

        # Extraer IPs (excluir privadas/loopback)
        for ip in ip_re.findall(val):
            parts = [int(p) for p in ip.split(".")]
            is_private = (
                parts[0] == 10
                or parts[0] == 127
                or (parts[0] == 172 and 16 <= parts[1] <= 31)
                or (parts[0] == 192 and parts[1] == 168)
            )
            if not is_private:
                ips.add(ip)

    return {
        "domains": sorted(domains),
        "urls":    sorted(urls),
        "ips":     sorted(ips),
    }


def extract_filesystem_iocs(decoded: dict) -> list[str]:
    """
    Extrae rutas de archivos y directorios del sistema.
    
    Busca rutas de Windows con variables de entorno (%APPDATA%, etc.)
    y rutas Unix/Linux (/tmp/, /home/, etc.).
    """
    paths: set[str] = set()

    # Rutas Windows con variables de entorno
    win_re = re.compile(
        r"(?:%[A-Z_]+%|[A-Z]:\\)[\\\/][\\\w\s\.\-\%]+",
        re.IGNORECASE,
    )
    # Variables de entorno sin letra de unidad
    env_re = re.compile(
        r"(?:APPDATA|TEMP|LOCALAPPDATA|USERPROFILE|PROGRAMFILES)\\[\\\w\.\-]+",
        re.IGNORECASE,
    )
    # Rutas Unix
    unix_re = re.compile(r"\/(?:home|tmp|var|opt)\/[\w\/\.\-]+")

    for val in decoded.values():
        for p in win_re.findall(val) + env_re.findall(val) + unix_re.findall(val):
            if len(p) > 8:
                paths.add(p)

    return sorted(paths)


def extract_behavioral_iocs(decoded: dict) -> dict:
    """
    Extrae indicadores de comportamiento: persistencia, ejecución, exfiltración.
    
    Estos no son IOCs de red o archivo, sino patrones de comportamiento
    útiles para reglas de detección y análisis dinámico.
    """
    behaviors: dict[str, list[str]] = {
        "persistence": [],
        "execution":   [],
        "c2_protocol": [],
        "encoding":    [],
    }
    for idx, val in decoded.items():
        vl = val.lower()
        if any(k in vl for k in ["setloginitemsettings", "openatlogin", "hkcu", "run\\"]):
            behaviors["persistence"].append(f"[{idx}] {val}")
        if any(k in vl for k in ["exec(", "eval(", "spawn(", "child_process"]):
            behaviors["execution"].append(f"[{idx}] {val}")
        if any(k in vl for k in ["post", "content-type", "application/json"]):
            behaviors["c2_protocol"].append(f"[{idx}] {val}")
        if val in ["base64", "utf8", "hex", "latin1"]:
            behaviors["encoding"].append(f"[{idx}] {val}")

    return behaviors


def hash_files(directory: str) -> list[dict]:
    """
    Calcula SHA256, SHA1 y MD5 de todos los archivos en el directorio.
    
    Útil para documentar las muestras antes de publicar los IOCs.
    Ignora archivos > 500MB para evitar problemas de memoria.
    """
    hashes = []
    for f in sorted(Path(directory).rglob("*")):
        if not f.is_file():
            continue
        if f.stat().st_size > 500_000_000:
            print(f"[!] Saltando {f.name} — demasiado grande (>500MB)", file=sys.stderr)
            continue
        try:
            data = f.read_bytes()
            hashes.append({
                "filename": f.name,
                "path":     str(f),
                "size":     len(data),
                "sha256":   hashlib.sha256(data).hexdigest(),
                "sha1":     hashlib.sha1(data).hexdigest(),
                "md5":      hashlib.md5(data).hexdigest(),
            })
        except Exception as e:
            print(f"[!] No se pudo hashear {f}: {e}", file=sys.stderr)
    return hashes


# ─── Generador STIX 2.1 ──────────────────────────────────────────────────────

def generate_stix(net_iocs: dict, file_hashes: list) -> str:
    """
    Genera un bundle STIX 2.1 con todos los IOCs.
    
    El bundle puede importarse directamente en:
      - AlienVault OTX
      - MISP
      - OpenCTI
      - Cualquier plataforma compatible con STIX 2.1
    
    No requiere la librería stix2 — genera el JSON directamente.
    """
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    indicators = []

    # Indicadores de dominio
    for domain in net_iocs.get("domains", []):
        indicators.append({
            "type":            "indicator",
            "spec_version":    "2.1",
            "id":              f"indicator--{uuid.uuid4()}",
            "created":         now,
            "modified":        now,
            "name":            f"Dominio malicioso: {domain}",
            "description":     "Infraestructura confirmada de la campaña ClickFix draw.io Electron RAT",
            "indicator_types": ["malicious-activity"],
            "pattern":         f"[domain-name:value = '{domain}']",
            "pattern_type":    "stix",
            "valid_from":      now,
            "labels":          ["malicious-activity", "clickfix", "rat"],
        })

    # Indicadores de URL
    for url in net_iocs.get("urls", []):
        indicators.append({
            "type":            "indicator",
            "spec_version":    "2.1",
            "id":              f"indicator--{uuid.uuid4()}",
            "created":         now,
            "modified":        now,
            "name":            "URL maliciosa — ClickFix campaign",
            "description":     url,
            "indicator_types": ["malicious-activity"],
            "pattern":         f"[url:value = '{url}']",
            "pattern_type":    "stix",
            "valid_from":      now,
            "labels":          ["malicious-activity", "clickfix"],
        })

    # Indicadores de hash de archivo
    for h in file_hashes:
        indicators.append({
            "type":            "indicator",
            "spec_version":    "2.1",
            "id":              f"indicator--{uuid.uuid4()}",
            "created":         now,
            "modified":        now,
            "name":            f"Archivo malicioso: {h['filename']}",
            "description":     f"SHA256: {h['sha256']} | Tamaño: {h['size']} bytes",
            "indicator_types": ["malicious-activity"],
            "pattern":         f"[file:hashes.SHA256 = '{h['sha256']}']",
            "pattern_type":    "stix",
            "valid_from":      now,
            "labels":          ["malicious-activity", "clickfix", "electron-rat"],
        })

    bundle = {
        "type":          "bundle",
        "id":            f"bundle--{uuid.uuid4()}",
        "spec_version":  "2.1",
        "objects":       indicators,
    }
    return json.dumps(bundle, indent=2, ensure_ascii=False)


# ─── Reporte en consola ───────────────────────────────────────────────────────

def print_report(net_iocs: dict, fs_iocs: list, behaviors: dict, hashes: list) -> None:
    """Imprime el reporte de IOCs de forma legible en consola."""
    print("\n" + "=" * 60)
    print("REPORTE DE IOCs — ClickFix draw.io Electron RAT")
    print(f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}")
    print("TLP: WHITE")
    print("=" * 60)

    # Dominios
    domains = net_iocs.get("domains", [])
    print(f"\n[DOMINIOS] ({len(domains)}) — bloquear en DNS/proxy/firewall")
    for d in domains:
        defanged = d.replace(".", "[.]")
        print(f"  {defanged}")

    # URLs
    urls = net_iocs.get("urls", [])
    print(f"\n[URLs] ({len(urls)})")
    for u in urls:
        defanged = u.replace("https://", "hxxps://").replace("http://", "hxxp://")
        defanged = defanged.replace(".", "[.]", 2)
        print(f"  {defanged}")

    # IPs
    ips = net_iocs.get("ips", [])
    if ips:
        print(f"\n[IPs] ({len(ips)})")
        for ip in ips:
            print(f"  {ip}")

    # Filesystem
    if fs_iocs:
        print(f"\n[FILESYSTEM] ({len(fs_iocs)}) — si existen, equipo infectado")
        for p in fs_iocs:
            print(f"  {p}")

    # Hashes
    if hashes:
        print(f"\n[HASHES DE ARCHIVOS] ({len(hashes)})")
        for h in hashes:
            print(f"  {h['filename']}")
            print(f"    SHA256: {h['sha256']}")
            print(f"    MD5:    {h['md5']}")
            print(f"    Tamaño: {h['size']:,} bytes")

    # Comportamiento
    print("\n[COMPORTAMIENTO]")
    for cat, items in behaviors.items():
        if items:
            print(f"  {cat.upper()}:")
            for item in items[:3]:
                print(f"    {item}")

    print()


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extractor de IOCs para ClickFix draw.io Electron RAT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # IOCs básicos
  python3 clickfix_ioc_extractor.py --strings deobfuscated_strings.json

  # Con hashes de muestras + bundle STIX
  python3 clickfix_ioc_extractor.py \\
      --strings deobfuscated_strings.json \\
      --samples ./muestras/ \\
      --stix \\
      --output iocs_completos.json
        """,
    )
    parser.add_argument(
        "--strings", "-s",
        required=True,
        help="JSON generado por clickfix_deobfuscate.py",
    )
    parser.add_argument(
        "--samples", "-d",
        default=None,
        help="Directorio con muestras de malware para hashear",
    )
    parser.add_argument(
        "--stix",
        action="store_true",
        help="Generar bundle STIX 2.1 para OTX/MISP",
    )
    parser.add_argument(
        "--output", "-o",
        default="iocs_completos.json",
        help="Archivo de salida (default: iocs_completos.json)",
    )
    args = parser.parse_args()

    # Cargar strings desobfuscados
    try:
        decoded: dict = json.loads(Path(args.strings).read_text())
    except FileNotFoundError:
        print(f"[-] No se encontró: {args.strings}", file=sys.stderr)
        print(f"    Ejecuta primero: python3 clickfix_deobfuscate.py electron.js", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Procesando {len(decoded)} strings desobfuscados...")

    # Extraer IOCs
    net_iocs   = extract_network_iocs(decoded)
    fs_iocs    = extract_filesystem_iocs(decoded)
    behaviors  = extract_behavioral_iocs(decoded)
    hashes     = hash_files(args.samples) if args.samples else []

    # Mostrar reporte
    print_report(net_iocs, fs_iocs, behaviors, hashes)

    # Guardar JSON completo
    output_data = {
        "metadata": {
            "campaign":     "ClickFix-DrawIO-ElectronRAT",
            "generated":    datetime.now(timezone.utc).isoformat(),
            "tlp":          "WHITE",
            "source_file":  args.strings,
        },
        "network":    net_iocs,
        "filesystem": fs_iocs,
        "behaviors":  behaviors,
        "hashes":     hashes,
    }
    Path(args.output).write_text(json.dumps(output_data, indent=2, ensure_ascii=False))
    print(f"[+] IOCs guardados en: {args.output}")

    # Generar STIX si se pidió
    if args.stix:
        stix_path = args.output.replace(".json", ".stix.json")
        stix_bundle = generate_stix(net_iocs, hashes)
        Path(stix_path).write_text(stix_bundle)
        print(f"[+] Bundle STIX 2.1 guardado en: {stix_path}")
        print(f"    Importar en OTX: otx.alienvault.com → Create Pulse → Import STIX")
        print(f"    Importar en MISP: Events → Add Event → Import STIX 2")


if __name__ == "__main__":
    main()
