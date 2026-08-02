# Plan delta de ejecución eSE 9.1.0-rc.3

## 1. Candidato padre

- Padre: `9.1.0-rc.2`.
- Commit de producto: `08aa6521f7d7907edb3584266abc3a9e31693161`.
- Decisión conservada: `NO_GO`, con 11 PASS, 0 FAIL y 16 BLOCKED.
- Motivo de sustitución: `V91-I05` demostró que una fuente explícita de enlace
  quedaba inerte si eD2K y Kad estaban desconectados.

La evidencia de RC.2 permanece inmutable y no se presenta como evidencia de
RC.3.

## 2. Congelación exacta de RC.3

1. Revisar la procedencia `SF_LINK` y la excepción limitada a HighID.
2. Ejecutar la regresión directa de 64 MiB con eD2K y Kad desconectados.
3. Ejecutar los self-tests del agente y del kit de descarga.
4. Confirmar el preflight de `v0.70b-eSE9.1.0-rc.3`.
5. Crear un único commit de producto, versión, especificación y laboratorio.
6. Compilar y empaquetar desde ese commit limpio.
7. Registrar commit, SHA-256 y tamaño del ZIP, `emule.exe`,
   `ese-server.exe` y `BUILD_INFO.txt`.

Ningún binario de desarrollo ni evidencia de RC.2 puede producir un PASS de
RC.3.

## 3. Puertas locales

El candidato exacto debe superar:

1. `Release|x64`.
2. Core gate.
3. Integration gate.
4. Self-test del paquete.
5. Regresión de enlace directo sin redes de descubrimiento.
6. Self-tests del agente desatendido y del kit `V91-I05`.
7. Verificación del manifiesto y de la identidad empaquetada.

Un fallo rechaza el candidato antes de modificar la red física.

## 4. Campaña física V91-I05

Topología obligatoria:

- H1: origen físico y coordinador.
- H3: portátil físico con el agente desatendido.
- El canal de control puede usar la red privada de laboratorio.
- El tráfico de datos eMule debe usar exclusivamente las direcciones físicas
  declaradas por el contrato.

Secuencia:

1. Desplegar en H3 el ZIP RC.3 y el runner cuyos hashes fija el contrato.
2. Verificar que no existen procesos, reglas ni perfiles huérfanos.
3. Crear el fixture canónico determinista de 4 GiB.
4. Compartirlo desde H1 e inyectar una sola fuente directa en H3.
5. Mantener eD2K y Kad desconectados en el descargador.
6. Atribuir el socket de datos al PID, adaptador y pareja física exactos.
7. Completar la transferencia y reconstrucción sin huecos.
8. Verificar tamaño y SHA-256 del archivo recibido.
9. Ejecutar y documentar la limpieza en ambos equipos.

## 5. Criterio PASS

`V91-I05` es PASS solamente si:

- ambos hosts ejecutan el mismo candidato RC.3 exacto;
- el ZIP, ejecutable y commit coinciden con el contrato;
- existe un socket eMule directo entre las direcciones físicas esperadas;
- no se usa la red privada de control como ruta de datos;
- la transferencia de 4 GiB termina sin huecos ni corrupción;
- todos los hashes y tamaños coinciden;
- no queda ningún proceso, regla de firewall o perfil temporal del caso.

Un problema del producto es `FAIL`. Una limitación externa reproducible que
impida observar el criterio es `LAB_BLOCKED`; nunca se convierte
automáticamente en PASS.

## 6. Promoción

Tras `V91-I05`, se crea el ledger RC.3 ligado al commit y al paquete exactos.
Los casos no afectados pueden citar evidencia anterior como contexto, pero
cualquier caso requerido por la política de promoción debe conservar una
identidad comprobable. RC.3 seguirá siendo `NO_GO` mientras la matriz no
alcance el umbral definido por la especificación v9.1.

## 7. Resultado ejecutado

`V91-I05` es **PASS** para el candidato exacto:

- producto: commit `815b45ca7a1415bd3e06ff043d53794bc340b346`;
- ZIP: `359272c764c532c32cfd97eeb92e2db4feaa620c5d3f6318a82a7453dbf1b56f`,
  212.040.831 bytes;
- fixture: 4.294.967.296 bytes, SHA-256
  `1016d6f63ae1649a879a7c0de30865ed132deb37b1c3b2bc9ca004c88feee26c`
  y ED2K `796A95E75DF8E78D54A57CDEA1FEDE84`;
- flujo: una única tupla física H3 -> H1, con los endpoints redactados,
  131.877 paquetes exactos y cero paquetes peer IPv6 o de terceros;
- wire: una petición `C5:A3`, 10.711 respuestas `C5:40` y cero firmas
  inválidas;
- captura: ETW sin pérdidas, PCAPNG de 32.278.712 bytes y limpieza
  `CLEANUP_COMPLETE`;
- validación central: 11 entradas compactas y 12 artefactos raw aceptados.

La ejecución original quedó `LAB_BLOCKED` dentro del adjudicador post-captura
porque PktMon declaró Ethernet para tramas Wi-Fi 802.11 y el parser antiguo no
las decapsulaba. No se repitió ni modificó el producto: se conservaron los
artefactos brutos y el cleanup, se corrigió y probó el adjudicador, se
reconstruyó el paquete compacto y H1 volvió a validar el expediente completo.

Evidencia de cierre:

- `V91_RC3_I05_RESULT.json`;
- COMPLETE remoto SHA-256
  `fe69689bce809a4f0d9514c4e72bdf0ee9f19b26766e78c91f4f43ebfae39381`;
- informe central SHA-256
  `c451b5f7876d7f6badf7c54693e312bde9dc26e3735e5e634b4841e920d42438`.

La matriz RC.3 queda en **12 PASS, 0 FAIL y 15 BLOCKED**, por lo que la
decisión global continúa siendo `NO_GO`.
