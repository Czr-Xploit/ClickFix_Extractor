#!/usr/bin/env python3
"""
clickfix_deobfuscate.py
=======================
Desobfuscador automático para la campaña ClickFix draw.io Electron RAT.

Decodifica el array de strings ofuscados en electron.js usando el esquema:
    RC4 stream cipher + Base64 con alfabeto personalizado (minúsculas primero)

Campaña analizada:
    Entrega:  fepafut[.]com
    C2:       chimefusion[.]com
    Stager:   cudmcx[.]xyz/u
    Dropper:  ccudmcx[.]xyz/update.zip

Uso:
    python3 clickfix_deobfuscate.py electron.js
    python3 clickfix_deobfuscate.py electron.js --verbose
    python3 clickfix_deobfuscate.py electron.js --output resultado.json

TLP:WHITE | https://github.com/tu-handle/clickfix-drawio-electron-rat
"""

import re
import sys
import json
import argparse
import urllib.parse
from pathlib import Path


# ─── Algoritmo de desobfuscación ─────────────────────────────────────────────

# Alfabeto Base64 personalizado que usa el malware
# Diferencia con el estándar: minúsculas primero (a-z antes que A-Z)
# Estándar:     ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=
# Personalizado:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=
ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="


def custom_b64_decode(s: str) -> str:
    """
    Decodifica Base64 con el alfabeto personalizado del malware.
    
    El malware reordena el alfabeto poniendo minúsculas primero para
    evitar que decodificadores estándar funcionen directamente.
    """
    bits, bit_count, output = 0, 0, []
    for ch in s:
        val = ALPHABET.find(ch)
        if val == -1 or ch == "=":
            continue
        bits = (bits << 6) | val
        bit_count += 6
        if bit_count >= 8:
            bit_count -= 8
            output.append((bits >> bit_count) & 0xFF)
    try:
        # URL decode para manejar caracteres especiales
        return urllib.parse.unquote("".join(f"%{b:02X}" for b in output))
    except Exception:
        return bytes(output).decode("latin-1", errors="replace")


def rc4_decrypt(key: str, data: str) -> str:
    """
    Descifra usando RC4 (Rivest Cipher 4).
    
    Cada string en el malware tiene su propia clave RC4 única,
    pasada como segundo argumento a la función bx(índice, clave).
    """
    # Key Scheduling Algorithm (KSA)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    # Pseudo-Random Generation Algorithm (PRGA)
    i = j = 0
    out = []
    for ch in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(chr(ord(ch) ^ S[(S[i] + S[j]) % 256]))
    return "".join(out)


def decode(encoded: str, key: str) -> str | None:
    """
    Decodifica un string del array usando Base64 custom → RC4.
    Retorna None si falla (string corruptor o clave incorrecta).
    """
    try:
        return rc4_decrypt(key, custom_b64_decode(encoded))
    except Exception:
        return None


# ─── Extracción del archivo ───────────────────────────────────────────────────

def extract_string_array(code: str) -> list[str]:
    """
    Extrae el array de 1.015 strings ofuscados del electron.js.
    
    En el código fuente aparece como:
        function c() { const W = ["string1","string2",...]; c=function(){return W}; return c() }
    
    Intenta múltiples patrones para mayor compatibilidad con variantes.
    """
    patterns = [
        # Patrón principal de esta campaña
        r'function c\(\)\{const W=\[(.+?)\];c=function',
        # Variante alternativa
        r'const W=\[(.+?)\];\s*c\s*=\s*function',
        # Patrón genérico para arrays grandes
        r'=\[("(?:[^"\\]|\\.)*"(?:\s*,\s*"(?:[^"\\]|\\.)*")+)\]',
    ]
    for pattern in patterns:
        match = re.search(pattern, code, re.DOTALL)
        if match:
            try:
                arr = json.loads("[" + match.group(1) + "]")
                # Solo aceptar si tiene suficientes elementos (array real, no decorativo)
                if len(arr) > 100:
                    return arr
            except Exception:
                continue
    return []


def extract_key_map(code: str) -> dict[int, str]:
    """
    Extrae el mapa índice → clave RC4 buscando todas las llamadas bx(índice, "clave").
    
    En el código aparece como:
        bx(264,"hH#x")  →  índice 264 usa clave "hH#x"  →  decodifica a "chimefusion.com/u/"
    
    Solo guarda la primera ocurrencia por índice (la relevante).
    """
    pattern = re.compile(r'bx\((\d+),"([^"]+)"\)')
    key_map: dict[int, str] = {}
    for idx_str, key in pattern.findall(code):
        idx = int(idx_str)
        if idx not in key_map:
            key_map[idx] = key
    return key_map


# ─── Categorización de resultados ────────────────────────────────────────────

# Palabras clave para clasificar strings por categoría
CATEGORIES = {
    "C2_NETWORK": [
        "http", "://", "chimefusion", "cudmcx", "ccudmcx",
        "post", "application/json", "content-type"
    ],
    "FILESYSTEM": [
        "appdata", "temp", "\\", "cache", "setup.txt",
        "demo.log", "runner", "updateapp", "microsoft"
    ],
    "EXECUTION": [
        "exec", "eval", "spawn", "child_process"
    ],
    "PERSISTENCE": [
        "loginitem", "openatlogin", "setloginitemsettings", "run\\"
    ],
    "MODULES": [
        "electron", "fs/promises", "path", "url", "https",
        "electron-log", "electron-store", "electron-updater",
        "pdf-lib", "commander", "crc", "zlib"
    ],
}


def categorize(results: dict[int, str]) -> dict[str, list[tuple[int, str]]]:
    """Clasifica los strings decodificados por categoría de interés."""
    cats: dict[str, list] = {k: [] for k in CATEGORIES}
    cats["OTHER"] = []

    for idx, val in sorted(results.items()):
        vl = val.lower()
        matched = False
        for cat, keywords in CATEGORIES.items():
            if any(kw in vl for kw in keywords):
                cats[cat].append((idx, val))
                matched = True
                break
        if not matched:
            cats["OTHER"].append((idx, val))

    return cats


# ─── Análisis principal ───────────────────────────────────────────────────────

def analyze(filepath: str) -> dict[int, str]:
    """
    Función principal: lee el archivo, extrae y decodifica todos los strings.
    
    Retorna un diccionario {índice: string_decodificado}.
    """
    code = Path(filepath).read_text(encoding="utf-8", errors="replace")

    # 1. Extraer array de strings
    strings = extract_string_array(code)
    if not strings:
        print("[-] No se pudo extraer el array de strings.", file=sys.stderr)
        print("    Verifica que el archivo sea un electron.js de esta campaña.", file=sys.stderr)
        return {}

    # 2. Extraer mapa de claves
    key_map = extract_key_map(code)
    if not key_map:
        print("[-] No se encontraron llamadas bx(). El archivo puede ser diferente.", file=sys.stderr)
        return {}

    # 3. Calcular offset base (índice mínimo en el mapa)
    base_offset = min(key_map.keys())

    print(f"[+] Array de strings:  {len(strings):,} elementos")
    print(f"[+] Mappings de claves: {len(key_map):,} encontrados")
    print(f"[+] Offset base:        {base_offset}")

    # 4. Decodificar todos los strings
    results: dict[int, str] = {}
    for idx, key in key_map.items():
        pos = idx - base_offset
        if 0 <= pos < len(strings):
            decoded = decode(strings[pos], key)
            if decoded:
                results[idx] = decoded

    return results


def print_results(cats: dict, results: dict, verbose: bool = False) -> None:
    """Imprime los resultados categorizados en la consola."""
    print("\n" + "=" * 60)
    print("STRINGS DESOBFUSCADOS")
    print("=" * 60)

    # Siempre mostrar categorías de alto valor
    priority = ["C2_NETWORK", "PERSISTENCE", "EXECUTION", "FILESYSTEM"]
    for cat in priority:
        items = cats.get(cat, [])
        if items:
            print(f"\n{'─'*40}")
            print(f"  {cat} ({len(items)} strings)")
            print(f"{'─'*40}")
            for idx, val in items:
                print(f"  [{idx:4d}]  {val}")

    # Mostrar módulos y otros solo en modo verbose
    if verbose:
        for cat in ["MODULES", "OTHER"]:
            items = cats.get(cat, [])
            if items:
                print(f"\n  {cat} ({len(items)} strings)")
                for idx, val in items:
                    print(f"  [{idx:4d}]  {val}")

    print(f"\n{'='*60}")
    print(f"  Total decodificados: {len(results)}")
    print(f"{'='*60}")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Desobfuscador RC4+Base64 para ClickFix draw.io Electron RAT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 clickfix_deobfuscate.py electron.js
  python3 clickfix_deobfuscate.py electron.js --verbose
  python3 clickfix_deobfuscate.py electron.js --output mi_analisis.json
        """,
    )
    parser.add_argument(
        "file",
        help="Ruta al electron.js del malware",
    )
    parser.add_argument(
        "--output", "-o",
        default="deobfuscated_strings.json",
        help="Archivo JSON de salida (default: deobfuscated_strings.json)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Mostrar también módulos y strings sin categorizar",
    )
    args = parser.parse_args()

    print(f"[*] Analizando: {args.file}")

    results = analyze(args.file)
    if not results:
        sys.exit(1)

    cats = categorize(results)
    print_results(cats, results, args.verbose)

    # Guardar JSON completo
    out_data = {str(k): v for k, v in sorted(results.items())}
    Path(args.output).write_text(json.dumps(out_data, indent=2, ensure_ascii=False))
    print(f"\n[+] Resultados guardados en: {args.output}")
    print(f"    Usar clickfix_ioc_extractor.py --strings {args.output} para extraer IOCs")


if __name__ == "__main__":
    main()
