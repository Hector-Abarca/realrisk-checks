# RealRisk · Verificadores de autodiagnóstico

Verificadores de **autodiagnóstico** publicados por [Asentic](https://www.asentic.cl) como
complemento de [**RealRisk**](https://realrisk.asentic.cl). Su único propósito es que un equipo
de defensa pueda comprobar **si sus propios sistemas son vulnerables a un CVE** — mirando el
estado real (paquete instalado, build, configuración), no solo el banner de versión.

No son herramientas ofensivas. No contienen exploits armados. Cada verificador es de **código
fuente, en un solo archivo, sin dependencias, legible y auditable antes de ejecutarlo**.

> Léelo antes de correrlo. Ese es el punto.

## Cómo usar un verificador

1. Entra a la carpeta del CVE (p. ej. `CVE-2026-41089/`).
2. **Lee el código completo.** Es corto, sin ofuscar y usa solo la biblioteca estándar.
3. Verifica su integridad contra el manifiesto:
   ```bash
   sha256sum CVE-2026-41089/check_cve_2026_41089.py
   # compara con el campo "sha256" de ese CVE en index.json
   ```
4. Ejecútalo **solo contra sistemas de tu propiedad o con autorización explícita por escrito**
   (ver [`SECURITY.md`](SECURITY.md)). Las instrucciones de ejecución viven en el `README.md`
   de cada carpeta de CVE.

Salida de todo verificador: `VULNERABLE` / `NO_VULNERABLE` / `NO_CONCLUYENTE`, con la evidencia.

## Los tres niveles de riesgo

| Nivel | Nombre | Qué hace | Impacto |
|---|---|---|---|
| 1 | pasivo | Observa: versión, banner, config, presencia de endpoint | Nulo |
| 2 | sonda activa benigna | Petición legítima y observa la respuesta. Sin payload ni escritura | Mínimo |
| 3 | confirmación | Dispara la condición lo justo para confirmarla — **parece exploit, no lo es** | Controlado, no destructivo |

La línea es estricta en todos los niveles: **confirma el estado vulnerable sin lograr la
explotación ni causar daño.** Nunca ejecución de código, nunca escritura destructiva, nunca
exfiltración, nunca DoS. El contrato completo está en [`SECURITY.md`](SECURITY.md) y se valida
automáticamente en CI antes de aceptar cualquier verificador.

## Garantías de todo verificador

Un solo archivo · biblioteca estándar (sin dependencias transitivas) · sin telemetría ni
llamadas a casa · no destructivo (solo lectura, una pasada, sin ramp) · salida clara · cabecera
honesta (qué hace, qué envía, qué **no** hace y su nivel) · hash SHA-256 publicado en
[`index.json`](index.json) · código sin ofuscar.

## Estructura del repo

```
realrisk-checks/
├── index.json                 ← manifiesto que lee RealRisk (CVE → script, nivel, hash)
├── SECURITY.md                ← contrato de seguridad (qué garantiza cada verificador)
├── CONTRIBUTING.md            ← cómo se escribe y aprueba un verificador
├── LICENSE                    ← MIT
├── tools/
│   ├── validate_contract.py   ← valida el contrato (lo corre la CI)
│   └── check_template.py      ← plantilla con la cabecera estándar
└── CVE-XXXX-XXXX/
    ├── check_cve_xxxx_xxxx.py  ← un archivo, biblioteca estándar
    └── README.md               ← instalación + ejecución + ejemplos
```

## Cómo se conecta con RealRisk

RealRisk lee este [`index.json`](index.json) (cacheado, vía `raw.githubusercontent`) y enciende
un badge **"Verificador disponible"** en la ficha del CVE correspondiente, enlazando acá. Todo
el texto de instalación/ejecución vive en este repo (fuente única de verdad). Publicar un
verificador + actualizar el índice enriquece la ficha sola.

## Reporte de problemas

Si encuentras un comportamiento que se aparte del contrato, escríbenos a **contacto@asentic.cl**.
Tratamos cualquier desvío como un incidente de seguridad.

---

Una herramienta de [Asentic](https://www.asentic.cl) · *Ciberseguridad que protege y habilita*
