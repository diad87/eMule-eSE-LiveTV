# eSE — Delta de baseline eMule AI 1.6

Estado: delta registrado; no sustituye retrospectivamente el baseline 1.5.2  
Fecha de registro: 15 de agosto de 2026  
Momento de promoción: freeze Stable de eSE 9.2

## 1. Procedencia y autoridad

| Referencia | Valor |
|---|---|
| Baseline histórico | `eMuleAI_v1.5.2` |
| Commit histórico | `de8e27e2029044d533f7090f173c95856fe4635a` |
| Baseline público actual | [`eMuleAI_v1.6`](https://github.com/eMuleAI/eMuleAI/releases/tag/eMuleAI_v1.6) |
| Commit del tag 1.6 | `a2f05dc8db772a11ca874adf0a16baaf30560519` |
| Inventario histórico | `EMULEAI_PARITY_AND_SUPERIORITY_PROGRAM.md` |
| Asignación temporal | `EMULEAI_INTEGRATED_RELEASE_ROADMAP.md` |

El inventario de 49 funciones y 43 mejoras permanece congelado contra 1.5.2
para que sus 92 comparaciones y evidencias sigan siendo reproducibles. Este
documento registra el cambio observado en 1.6 sin reescribir aquel histórico.

A partir del freeze Stable de 9.2, un nuevo veredicto `ESE-SUPERA` deberá pasar
contra ambos referentes: el histórico 1.5.2 y el baseline vigente promovido. Si
aparece otra release pública antes del freeze, se crea otro delta; no se cambia
silenciosamente este commit.

## 2. Crosswalk completo de la release 1.6

Los identificadores `AI16-Dxx` pertenecen solo a esta capa de delta. No son
casos nuevos de la matriz `AI-Fxx`/`AI-Ixx` y no se cuentan otra vez en el mapa
de 92 cierres.

| Delta | Cambio de 1.6 | Propietario existente | Ventana prevista | Evidencia que se añade |
|---|---|---|---|---|
| `AI16-D01` | Revisión del Download Validator | `AI-F21`, `AI-I32`, `AI-F28`, `AI-F13` | `AI-F21→V95`; `AI-I32/AI-F28/AI-F13→V96` | motor y corpus en V95; página de opciones, reglas configurables y coincidencias visibles bajo resultados de búsqueda en V96; el delta no cierra hasta pasar ambos tramos |
| `AI16-D02` | Menor huella de traducciones en el ejecutable | `AI-F22` | `V96` | tamaño por idioma, cobertura, placeholders y fallback medidos |
| `AI16-D03` | Tooltips ampliados | `AI-F42`, `AI-I32` | `V96` | cobertura accesible, procedencia de datos y ausencia de dato autodeclarado presentado como hecho |
| `AI16-D04` | Opciones, DPI, layout y ayuda corregidos | `AI-F12`, `AI-I32`, `AI-I34` | `V96` | matriz DPI/high-contrast/teclado y capturas de regresión |
| `AI16-D05` | País y ciudad en detalles de cliente | `AI-F30`, `AI-F41`, `AI-I04` | `V96` | lookup local IPv4/IPv6, privacidad y base reproducible |
| `AI16-D06` | Reset de preferencias | `AI-F46`, `AI-I32` | `V96` | reset por sección, preview, defaults versionados y rollback |
| `AI16-D07` | Mover todas las fuentes A4AF | `AI-F13`, `AI-I10` | `V96` | operación bulk cancelable, atómica por lote y GUI responsiva |
| `AI16-D08` | Multiselección en la lista de clientes | `AI-F13`, `AI-I10`, `AI-I18` | `V96` | selección estable, teclado, acciones bulk y límites con listas grandes |
| `AI16-D09` | Progreso traducido de arranque y cierre | `AI-F05`, `AI-F22` | `V96` | tareas reales, cancelación segura, traducción y cero truncado |
| `AI16-D10` | Menos falsos positivos de abuso tras una subida válida | `AI-F11`, `AI-F16` | `V97` | corpus etiquetado, explicación, caducidad y control negativo |
| `AI16-D11` | Corrección de Last Reception obsoleto | `AI-F07`, `AI-F13` | `V96` | reloj/frescura deterministas y actualización incremental de la lista |
| `AI16-D12` | Fuentes expandidas asociadas al fichero correcto | `AI-F13`, `AI-I07`, `AI-I08` | `V96` | identidad estable de fila y regresión con refresh concurrente |
| `AI16-D13` | Scroll de fuentes expandidas sin argumento inválido | `AI-F13`, `AI-I07` | `V96` | fuzz de índice, scroll y actualización concurrente |
| `AI16-D14` | “Asked another file” sin paréntesis vacíos | `AI-F13`, `AI-F42` | `V96` | presentación condicional y regresión de localización |
| `AI16-D15` | Indicadores de comentario y rating corregidos | `AI-F13`, `AI-F42` | `V96` | estados explícitos y refresco incremental sin datos stale |
| `AI16-D16` | Obfuscation dual-stack en LowID/firewall | `AI-F14`, `AI-F15` | `AI-F15→V92`; `AI-F14→V97` | regresión del contrato existente en V92; vector byte-exact IPv4/IPv6, LowID, fallback y control vanilla para el cierre de red en V97 |
| `AI16-D17` | Compatibilidad con tags legacy de subida MLDonkey | `AI-F11`, `AI-F16` | `V97` | corpus interop sin penalización falsa y límites de parser |
| `AI16-D18` | Menos falsos reportes agresivos por conflicto de hash | `AI-F11`, `AI-F16`, `AI-F21` | `AI-F21→V95`; `AI-F11/AI-F16→V97` | clasificación base y repetición en V95; corpus de protección y control adversarial en V97; cierre solo tras ambos tramos |
| `AI16-D19` | Retirada de reglas de phishing de username obsoletas | `AI-F11`, `AI-F16` | `V97` | reglas versionadas, justificación y tasa de falsos positivos |

## 3. Gate de promoción en el freeze de 9.2

La promoción del delta exige, en este orden:

1. volver a fijar tag, commit, release notes y licencia;
2. construir o adquirir de forma reproducible el binario de comparación;
3. ejecutar el diff de código y deduplicar cada cambio contra los 92 casos;
4. añadir corpus y vectores sin introducir producción, wire o UI en 9.2–9.4;
5. crear un caso nuevo solo si ningún `AI-Fxx`/`AI-Ixx` posee realmente el
   contrato; esa decisión actualizaría matriz, mapa y validador en el mismo
   cambio;
6. reestimar 9.5–9.8 y registrar desviaciones sin consumir sus reservas antes
   de que la release correspondiente tenga autoridad normativa.

Hasta pasar este gate, 1.6 es el **baseline actual candidato**. Sirve para no
planificar contra una versión obsoleta, pero no invalida cierres históricos ni
autoriza trabajo de producto.
