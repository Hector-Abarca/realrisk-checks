# Contrato de seguridad de los verificadores de RealRisk

Este repositorio contiene verificadores de autodiagnóstico publicados por Asentic como
complemento de RealRisk (https://realrisk.asentic.cl). Su único propósito es que un equipo
de defensa pueda comprobar si sus propios sistemas son vulnerables a un CVE.

No son herramientas ofensivas. No contienen exploits armados. Cada verificador es de código
fuente, en un solo archivo, legible y auditable antes de ejecutarlo.

## Autorización

Ejecuta estos verificadores **solo contra sistemas de tu propiedad o sobre los que tengas
autorización explícita por escrito**. Probar sistemas de terceros sin permiso es ilegal en la
mayoría de las jurisdicciones, incluida Chile (Ley 21.459). La responsabilidad es de quien
ejecuta el verificador.

## Los tres niveles de riesgo

- **Nivel 1 — pasivo.** Solo observa (versión, banner, config, paquete instalado). Impacto nulo.
- **Nivel 2 — sonda activa benigna.** Petición legítima, observa la respuesta. Sin payload ni
  escritura.
- **Nivel 3 — confirmación.** Dispara la condición lo justo para confirmarla. Puede parecer un
  exploit, pero no lo es: confirma el estado vulnerable **sin lograr la explotación ni causar
  daño**. Nunca ejecución de código, nunca escritura, nunca exfiltración, nunca DoS.

## Garantías de todos los verificadores

1. **Un solo archivo, biblioteca estándar.** Sin dependencias de terceros.
2. **Sin llamadas a casa.** Sin telemetría. La única red que tocan es el destino que declaras.
3. **No destructivo.** No escribe, no borra, no reinicia servicios.
4. **Seguro por defecto.** Solo lectura, una pasada, sin ramp (no provoca DoS).
5. **Salida clara:** `VULNERABLE` / `NO_VULNERABLE` / `NO_CONCLUYENTE`, con la evidencia.
6. **Cabecera honesta:** qué hace, qué envía, qué **no** hace y su nivel.

## Cómo validar la integridad antes de ejecutar

1. Lee el código completo (corto y sin ofuscar a propósito).
2. Verifica el hash contra `index.json`:
   ```bash
   sha256sum CVE-AAAA-NNNNN/check_cve_aaaa_nnnnn.py
   ```
3. Si hay firma en la release, valida la firma.

## Cómo se aprueba un verificador

Ninguno entra sin pasar la **revisión del contrato (validada en CI)**: un solo archivo, sin
dependencias de terceros, sin red salvo el destino declarado, sin acciones destructivas, con la
cabecera estándar y el nivel correctamente declarado, y con el hash del manifiesto cuadrando.
Trazabilidad en el historial de commits. El validador es [`tools/validate_contract.py`](tools/validate_contract.py).

## Reporte de problemas

Si encuentras un comportamiento que se aparte de este contrato, escríbenos a **contacto@asentic.cl**.
Tratamos cualquier desvío como un incidente de seguridad.

## Aviso

El software se entrega "tal cual", sin garantía. Está pensado para defensores que verifican su
propia exposición. El mal uso es responsabilidad de quien lo ejecuta.
