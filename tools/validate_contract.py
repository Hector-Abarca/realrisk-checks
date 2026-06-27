#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Valida el contrato de seguridad de los verificadores de RealRisk.

Lo corre la CI en cada push/PR y puede correrse localmente:

    python3 tools/validate_contract.py

Comprueba, para el manifiesto y cada verificador declarado en index.json:
  - index.json bien formado, con los campos requeridos.
  - La carpeta del CVE existe y contiene el script declarado + su README.md.
  - "Un solo archivo": no hay otros .py en la carpeta del CVE.
  - El SHA-256 del script cuadra con el del manifiesto.
  - La cabecera estándar está completa (qué hace / qué envía / qué NO hace / nivel / ...).
  - Solo biblioteca estándar: ningún import de terceros.
  - Sin construcciones destructivas (eval/exec, borrado de archivos, apertura en
    modo escritura, reinicio de servicios, etc.).

Solo biblioteca estándar. Sale con código !=0 si algo incumple el contrato.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX = ROOT / "index.json"

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Campos requeridos por entrada del manifiesto.
REQUIRED_FIELDS = [
    "cve", "titulo", "ruta", "script", "lenguaje", "requiere",
    "nivel", "nivel_nombre", "hace", "salida", "autorizacion_requerida",
    "version", "sha256", "publicado",
]

# Marcadores obligatorios de la cabecera honesta (ver check_template.py).
HEADER_MARKERS = ["CVE:", "Nivel:", "Qué hace:", "Qué envía:", "Qué NO hace:", "Salida:", "Contrato:"]

# Construcciones prohibidas (no destructivo / sin ejecución de código).
FORBIDDEN_PATTERNS = [
    (r"\beval\s*\(", "uso de eval()"),
    (r"\bexec\s*\(", "uso de exec()"),
    (r"\b__import__\s*\(", "uso de __import__()"),
    (r"\bcompile\s*\(", "uso de compile()"),
    (r"\bos\.system\s*\(", "os.system()"),
    (r"\bos\.remove\s*\(", "os.remove() — borrado"),
    (r"\bos\.unlink\s*\(", "os.unlink() — borrado"),
    (r"\bos\.rmdir\s*\(", "os.rmdir() — borrado"),
    (r"\bos\.removedirs\s*\(", "os.removedirs() — borrado"),
    (r"\bshutil\.rmtree\s*\(", "shutil.rmtree() — borrado recursivo"),
    (r"\bshutil\.move\s*\(", "shutil.move() — modificación"),
    (r"\bos\.truncate\s*\(", "os.truncate() — escritura"),
]

# Apertura de archivos en modo escritura/append (no destructivo = solo lectura).
OPEN_WRITE_RE = re.compile(
    r"""\bopen\s*\([^)]*['"][rbt]*[wax]\+?[rbt]*['"]""", re.DOTALL
)

# Módulos cuya presencia delata "llamar a casa" más allá del destino declarado
# se revisan a mano en code review; acá solo bloqueamos terceros (no-stdlib).
STDLIB = getattr(sys, "stdlib_module_names", None)


def _stdlib_names() -> set[str]:
    if STDLIB:
        return set(STDLIB) | {"__future__"}
    # Fallback mínimo para Python <3.10 (la CI usa 3.12).
    return {
        "__future__", "argparse", "ast", "base64", "collections", "contextlib",
        "csv", "datetime", "enum", "functools", "hashlib", "hmac", "http",
        "io", "ipaddress", "itertools", "json", "math", "os", "pathlib", "platform",
        "re", "shutil", "socket", "ssl", "struct", "subprocess", "sys", "time",
        "typing", "urllib", "uuid", "xml",
    }


def _imported_toplevel(tree: ast.AST) -> set[str]:
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                mods.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:  # ignora imports relativos
                mods.add(node.module.split(".")[0])
    return mods


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_script(entry: dict, errors: list[str]) -> None:
    cve = entry.get("cve", "?")
    ruta = ROOT / entry["ruta"]
    script = ruta / entry["script"]

    if not ruta.is_dir():
        errors.append(f"[{cve}] carpeta no existe: {entry['ruta']}")
        return
    if not script.is_file():
        errors.append(f"[{cve}] script no existe: {entry['ruta']}/{entry['script']}")
        return
    if not (ruta / "README.md").is_file():
        errors.append(f"[{cve}] falta README.md en {entry['ruta']}")

    # "Un solo archivo": no otros .py en la carpeta del CVE.
    otros = [p.name for p in ruta.glob("*.py") if p.name != entry["script"]]
    if otros:
        errors.append(f"[{cve}] debe ser un solo archivo; sobran .py: {otros}")

    # SHA-256.
    real = _sha256(script)
    if entry.get("sha256") != real:
        errors.append(f"[{cve}] sha256 no cuadra. index={entry.get('sha256')!r} real={real!r}")

    src = script.read_text(encoding="utf-8", errors="replace")

    # Cabecera honesta.
    for marker in HEADER_MARKERS:
        if marker not in src:
            errors.append(f"[{cve}] falta el marcador de cabecera obligatorio: '{marker}'")

    # Sintaxis + imports + AST.
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        errors.append(f"[{cve}] error de sintaxis: {e}")
        return

    terceros = _imported_toplevel(tree) - _stdlib_names()
    if terceros:
        errors.append(f"[{cve}] importa módulos de terceros (prohibido): {sorted(terceros)}")

    # Construcciones prohibidas.
    for pat, desc in FORBIDDEN_PATTERNS:
        if re.search(pat, src):
            errors.append(f"[{cve}] construcción prohibida: {desc}")
    if OPEN_WRITE_RE.search(src):
        errors.append(f"[{cve}] abre archivos en modo escritura (debe ser solo lectura)")

    # Nivel declarado coherente.
    if entry.get("nivel") not in (1, 2, 3):
        errors.append(f"[{cve}] nivel inválido: {entry.get('nivel')!r} (debe ser 1, 2 o 3)")


def main() -> int:
    errors: list[str] = []

    if not INDEX.is_file():
        print("ERROR: no existe index.json", file=sys.stderr)
        return 1

    try:
        index = json.loads(INDEX.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"ERROR: index.json no es JSON válido: {e}", file=sys.stderr)
        return 1

    for key in ("schema", "repo", "sitio", "contrato_seguridad", "actualizado", "verificadores"):
        if key not in index:
            errors.append(f"index.json: falta la clave de nivel superior '{key}'")

    verificadores = index.get("verificadores", [])
    if not isinstance(verificadores, list):
        errors.append("index.json: 'verificadores' debe ser una lista")
        verificadores = []

    vistos: set[str] = set()
    for entry in verificadores:
        cve = entry.get("cve", "?")
        for f in REQUIRED_FIELDS:
            if f not in entry:
                errors.append(f"[{cve}] falta el campo requerido '{f}'")
        if cve != "?" and not CVE_RE.match(cve):
            errors.append(f"[{cve}] formato de CVE inválido")
        if cve in vistos:
            errors.append(f"[{cve}] CVE duplicado en el manifiesto")
        vistos.add(cve)
        if all(f in entry for f in ("ruta", "script", "sha256")):
            validate_script(entry, errors)

    n = len(verificadores)
    if errors:
        print(f"✗ Contrato INCUMPLIDO — {len(errors)} problema(s) en {n} verificador(es):\n", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"✓ Contrato OK — {n} verificador(es) validado(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
