# Cómo se escribe y aprueba un verificador

Todo verificador de este repo debe cumplir el [contrato de seguridad](SECURITY.md), que se
valida automáticamente en CI ([`tools/validate_contract.py`](tools/validate_contract.py)). Nada
entra a `main` sin pasarlo.

## Pasos para agregar un verificador

1. **Crea la carpeta del CVE:** `CVE-AAAA-NNNNN/` (mayúsculas, igual que el identificador).
2. **Copia la plantilla** [`tools/check_template.py`](tools/check_template.py) a
   `CVE-AAAA-NNNNN/check_cve_aaaa_nnnnn.py` (nombre en minúsculas, guiones bajos).
3. **Completa la cabecera honesta** — todas estas líneas son obligatorias y las valida la CI:
   `CVE:`, `Nivel:`, `Qué hace:`, `Qué envía:`, `Qué NO hace:`, `Salida:`, `Contrato:`.
4. **Implementa `verificar()`** — solo lectura, una pasada, sin efectos secundarios. Solo
   biblioteca estándar. Salida `VULNERABLE` / `NO_VULNERABLE` / `NO_CONCLUYENTE`.
5. **Escribe el `README.md`** de la carpeta: qué hace, requisitos, instalación, ejecución con
   ejemplos, e interpretación de la salida. (Todo el texto de uso vive acá, no en RealRisk.)
6. **Calcula el hash** y registra el verificador en `index.json`:
   ```bash
   sha256sum CVE-AAAA-NNNNN/check_cve_aaaa_nnnnn.py
   ```
   Agrega una entrada a `verificadores` con todos los campos (ver los existentes como modelo) y
   actualiza el campo `actualizado` de nivel superior.
7. **Valida localmente** antes de subir:
   ```bash
   python3 tools/validate_contract.py
   ```

## Reglas duras (las fuerza la CI)

- **Un solo archivo** por verificador, **solo biblioteca estándar** (sin dependencias).
- **No destructivo:** nada de `eval`/`exec`, borrado de archivos, apertura en modo escritura,
  `os.system`, reinicio de servicios ni DoS.
- **Sin llamadas a casa:** la única red permitida es el destino que el usuario indica.
- **Hash del manifiesto cuadra** con el archivo.
- **Nivel correctamente declarado** (1 pasivo · 2 sonda activa benigna · 3 confirmación).

## Niveles

| Nivel | Qué puede hacer |
|---|---|
| 1 — pasivo | Leer versión/banner/config/paquete instalado. Sin tocar el servicio. |
| 2 — sonda activa benigna | Una petición legítima y observar la respuesta. Sin payload ni escritura. |
| 3 — confirmación | Disparar la condición lo justo para confirmarla, **sin explotar ni dañar**. |

Ante la duda, **baja el nivel** o marca `NO_CONCLUYENTE`. Un falso "NO_VULNERABLE" es peor que
un honesto "no pude determinarlo".
