#!/usr/bin/env python3
# RealRisk · Verificador de autodiagnóstico
# CVE: CVE-XXXX-XXXXX
# Nivel: 1 (pasivo)
# Qué hace: <una frase: qué observa para decidir, p. ej. compara la versión del paquete instalado con la build corregida>
# Qué envía: <qué sale a la red, si algo; "nada" para nivel 1 local>
# Qué NO hace: no envía payloads, no escribe ni borra nada, no ejecuta código en el destino, no hace DoS.
# Salida: VULNERABLE / NO_VULNERABLE / NO_CONCLUYENTE
# Contrato: https://github.com/Hector-Abarca/realrisk-checks/blob/main/SECURITY.md
# SPDX-License-Identifier: MIT
"""Plantilla de verificador de RealRisk.

Copia este archivo a CVE-XXXX-XXXXX/check_cve_xxxx_xxxxx.py, completa la cabecera
(todas las líneas son obligatorias y las valida la CI) e implementa `verificar()`.

Reglas del contrato (ver SECURITY.md, validado por tools/validate_contract.py):
  - Un solo archivo, SOLO biblioteca estándar (sin dependencias de terceros).
  - No destructivo: nada de escribir/borrar archivos, reiniciar servicios ni DoS.
  - Sin telemetría ni "llamadas a casa": la única red permitida es el destino declarado.
  - Salida clara y honesta.

Convención de salida (para poder encadenarlo en scripts):
  - NO_VULNERABLE   → exit 0
  - VULNERABLE      → exit 1
  - NO_CONCLUYENTE  → exit 2
"""
from __future__ import annotations

import argparse
import sys

VEREDICTOS = {"NO_VULNERABLE": 0, "VULNERABLE": 1, "NO_CONCLUYENTE": 2}


def verificar(args: argparse.Namespace) -> tuple[str, str]:
    """Devuelve (veredicto, evidencia). Implementa acá la lógica de detección.

    Debe ser solo lectura, una sola pasada, sin efectos secundarios.
    """
    # TODO: implementar la detección específica del CVE.
    return "NO_CONCLUYENTE", "Plantilla sin implementar."


def main() -> int:
    p = argparse.ArgumentParser(
        description="Verificador de autodiagnóstico de RealRisk (CVE-XXXX-XXXXX)."
    )
    # Ejemplo de argumentos típicos (ajusta a tu verificador):
    # p.add_argument("objetivo", help="host o ruta del sistema a verificar (tuyo o autorizado)")
    p.add_argument("--json", action="store_true", help="salida en JSON")
    args = p.parse_args()

    veredicto, evidencia = verificar(args)

    if args.json:
        import json
        print(json.dumps({"veredicto": veredicto, "evidencia": evidencia}, ensure_ascii=False))
    else:
        print(f"{veredicto}: {evidencia}")

    return VEREDICTOS.get(veredicto, 2)


if __name__ == "__main__":
    sys.exit(main())
