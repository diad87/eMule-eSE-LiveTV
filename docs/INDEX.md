# Índice maestro de documentación — eMule eSE LiveTV

> **Qué es esto:** el mapa único de toda la documentación del proyecto. Si no sabes por dónde
> empezar o dónde está algo, empieza aquí. Última actualización: **2026-06-14**.
>
> **Leyenda de estado:** 🎓 tesis/paper · 🧭 roadmap/estrategia viva · 📐 plan/spec ·
> ✅ implementado/final · 🔬 auditoría/análisis · 🔀 consolidado/comparativa · ♻️ a refrescar ·
> 📦 release/changelog · 📖 guía · ⏳ draft/gated · 🗄️ archivado

---

## 🚩 Empieza por aquí

| Documento | Para qué |
|---|---|
| [MODERNIZATION_ROADMAP.md](MODERNIZATION_ROADMAP.md) | **El plan director vivo.** Los 5 ejes de modernización (headless/API, buffer, IPTV, Kad-live, multiplataforma) + Track R (alcanzabilidad). Por aquí se decide qué se hace. |
| [MASTER_PLAN.md](MASTER_PLAN.md) | Visión de producto y escalabilidad (de ~20 a 5000+ viewers); arquitectura actual y cuellos de botella. |
| [USER_GUIDE.md](USER_GUIDE.md) | Cómo se usa: instalar, ver un stream, emitir, troubleshooting. |
| [CHANGELOG_vanilla0.70b_to_v8.1.0.md](CHANGELOG_vanilla0.70b_to_v8.1.0.md) | Qué cambia este fork frente a eMule 0.70b vanilla (la divergencia completa). |

---

## 🎓 Tesis y papers académicos

| Documento | Estado | Qué cubre |
|---|---|---|
| [THESIS_KAD_SIN_LOWID.md](THESIS_KAD_SIN_LOWID.md) | 🎓 v9, no implementado | Abolir el par LowID/HighID: identidad ≠ alcanzabilidad (vector `R` + cascada ICE). Capstone del Track R. |
| [PAPER_eSE_Live_ES.md](PAPER_eSE_Live_ES.md) · [_EN](PAPER_eSE_Live_EN.md) | 🎓 pre-print v1.0 | Paper sobre streaming en vivo P2P descentralizado sobre eD2K+Kad, sin trackers ni CDN (ES y EN). |

**Fuera del checkout principal** (viven en worktrees / ramas aparte — pueden no estar en `main`):

| Documento | Ubicación | Qué cubre |
|---|---|---|
| Tesis de privacidad eSE Live (9 caps. + README) | rama `claude/hungry-dhawan-84bd82` → `docs/thesis/` | Threat model, estado del arte, cripto, arquitectura de protocolo, análisis de seguridad/rendimiento, problemas abiertos, roadmap de implementación. |
| Monografía Kad Search v2 (10 caps. + bibliografía) | rama `claude/quizzical-newton-9aa3db` → `docs/thesis/kad-search-v2/` | Rediseño del subsistema de búsqueda Kad: marco teórico, análisis del Kad actual, diseño v2, privacidad, evaluación, modelo de amenaza. |

---

## 🧭 Estrategia: roadmaps y planes maestros

| Documento | Estado | Qué cubre |
|---|---|---|
| [MODERNIZATION_ROADMAP.md](MODERNIZATION_ROADMAP.md) | 🧭 vivo (2026-06-13) | **Director de ejecución.** 5 ejes en fases F0-F5 + Track R (R.0-R.5). Reglas: estabilizar primero, compat obligatoria. |
| [MASTER_PLAN.md](MASTER_PLAN.md) | 🧭 vivo | Plan de escalabilidad/producto: niveles de carga, puntos de ruptura, estado ideal. |
| [MODERNIZATION.md](MODERNIZATION.md) | 🔬 referencia | Inventario táctico de componentes vetustos (id3lib, CxImage, IE WebBrowser, CSocket…) con ROI y archivo:línea. 1/16 hecho (v143). *Complementa al ROADMAP, no lo sustituye.* |

---

## 📡 Track R — Alcanzabilidad: LowID / NAT-traversal / IPv6

> El plano de transporte, paralelo a los 5 ejes. **El mecanismo construye caminos; la tesis
> hace que los caminos sean lo único que existe.** Ver el track acoplado en el ROADMAP.

| Documento | Estado | Qué cubre |
|---|---|---|
| [LOWID_NAT_TRAVERSAL_PLAN.md](LOWID_NAT_TRAVERSAL_PLAN.md) | 📐 propuesta | El *mecanismo*: 5 fases (R.0 validar 2-vías → R.1 rendezvous 3-vías → R.2 keepalive → R.3 relay onion → R.4 IPv6). |
| [HOLEPUNCH_2PC_GATE_VALIDATION.md](HOLEPUNCH_2PC_GATE_VALIDATION.md) | 🧪 receta · ✅ GATE pasado (parcial) | **Gate R.0.** Receta 2-PC + resultado real: 2-vías PROBADO en NAT real (B→X success), pero NAT simétrica (B) no se abre ni con timing → relay. Contadores responder-side + matriz A→B vs B→A. |
| [R1_RENDEZVOUS_IMPL.md](R1_RENDEZVOUS_IMPL.md) | 📐 spec · ✅ implementado + validado 3-PC | **R.1 (3-vías).** Wire 0x68/69/6A/6B/6C + anti-reflexión por cookie. **COMPLETO Y RUNTIME-VALIDADO** (3-PC Tailscale: A→R REQ→CHALLENGE→cookie→FWD ejecutó, `fwd=1`/`success=1`). Cierre B-side E2E pendiente (known-contact gate + simétrica→relay). |
| [R3_RELAY_FLOOR_PLAN.md](R3_RELAY_FLOOR_PLAN.md) | 📐 spec · inc.1 hecho | **R.3 (relay floor).** El suelo de simétricas/CGNAT: el mecanismo onion YA existe (reusar exit-proxy+forward), falta `CLiveBuddyRelay` (100% stub) + fallthrough. Seguridad de relay (aceptación/ancho de banda/no-open-relay). Inc.1 (Tick+telemetría) hecho; inc.2-5 = accept/connect-out/cascade/3-PC. |
| [THESIS_KAD_SIN_LOWID.md](THESIS_KAD_SIN_LOWID.md) | 🎓 v9 | El *modelo*: registro de fuente v2 (`TAG_ESE_REACH`) + cascada `CReachPipeline` + muerte del concepto. |
| [REACH_HOST_ADAPTER_PLAN.md](REACH_HOST_ADAPTER_PLAN.md) | 📐 spec ejecutable | Puente `libreach`⇄eMule: `ReachHostAdapter` (C-ABI vtable, identidad por user-hash + late-bind anti-UAF, gancho en `RemoveClient`, transacción de ingest HELLO, reglas de byte-order, gate `ENABLE_ESE_LIBREACH_V9`). libreach L1+L2+L3 ya verde (190 checks); el adaptador es el siguiente paso MFC. |
| [IPV6_PLAN.md](IPV6_PLAN.md) | 📌 **canónico IPv6** (~25% hecho) | Plan maestro IPv6 (8 fases). Sprints 0-3 hechos, 4 scaffold, 5-11 sin iniciar. Scope: cliente↔servidor queda v4; v6 en cliente↔cliente, Kad, eSE/Live. |
| [IPV6_ANALYSIS.md](IPV6_ANALYSIS.md) | 🔀 comparativa | Por qué IPv6 es crítico + comparativa de enfoques. El elegido vive en IPV6_PLAN. |
| [IPV6_SPRINT_PLAN.md](IPV6_SPRINT_PLAN.md) | 🔀 operativo | Ejecución anti-regresión (flags, opcodes paralelos, smoke matrix). Canónico: IPV6_PLAN. |
| [ANONYMOUS_BROADCAST.md](ANONYMOUS_BROADCAST.md) | 📐 plan | Emitir sin publicar la IP del broadcaster en Kad (relay-protegido). Non-goal: no es Tor. |

---

## 🔢 Registro de protocolo (P0)

> Fuente única de verdad de los números de cable **del fork** (opcodes/tags/caps/tunnel). Antes de
> añadir un número nuevo: añade la fila y pasa el linter. **CI rojo hoy: 1 colisión real (`0xE0`).**

| Documento | Estado | Qué cubre |
|---|---|---|
| [protocol/PROTOCOL_REGISTRY.md](protocol/PROTOCOL_REGISTRY.md) | 🔢 gobierno | Registro + informe de conflictos + propuesta de migración. |
| [OPCODES](protocol/OPCODES.csv) · [TAGS](protocol/TAGS.csv) · [CAPABILITIES](protocol/CAPABILITIES.csv) · [TUNNEL_SERVICES](protocol/TUNNEL_SERVICES.csv) | 🔢 datos | CSV por namespace (96 entradas); el linter los valida. |
| [tools/check_protocol_registry.py](../tools/check_protocol_registry.py) | ✅ funciona | Gate de CI: duplicados, sin-registrar, drift doc-vs-código. |

---

## 📐 Versión v8.1.x — plan de versión y desgloses de sprint

| Documento | Estado | Qué cubre |
|---|---|---|
| [V8.1_SPRINT_PLAN.md](V8.1_SPRINT_PLAN.md) | 📐 plan de versión | Master de v8.1: Sprints A–E (data plane por túnel onion). Separa plano de control de datos. Sprints A/B ✅ (archivados). |
| [V8.1.1_SPRINT_E_BREAKDOWN.md](V8.1.1_SPRINT_E_BREAKDOWN.md) | 📐 **autoritativo E-α/E-β** | Chunks de vídeo por túnel a bitrate nativo (RS GF(256)). Cierra G1. **Manda sobre MASTER_PLAN/SPRINTS para E.** |

*(Desgloses de Sprint A/B y el análisis E-SPEED están en [Archivo histórico](#-archivo-histórico-docsarchive).)*

---

## 📐 Escalabilidad por etapas (sprints v2 → v4)

> *Estrella polar, no alcance vigente.* Definen el camino a decenas/cientos de miles de viewers;
> el trabajo real actual es v8.1.x. Útiles como dirección, no como spec inmediata.

| Documento | Estado | Qué cubre |
|---|---|---|
| [SPRINTS_V2.md](SPRINTS_V2.md) | 📐 plan | Del estado actual a 500-5000 viewers (observabilidad, transporte, descubrimiento). |
| [SPRINTS_V3.md](SPRINTS_V3.md) | 📐 plan | De 5k a 50k viewers (SRT, WebRTC; decisiones de diseño marcadas ⚠️). |
| [SPRINTS_V4.md](SPRINTS_V4.md) | 📐 exploratorio | 50k-500k viewers (SVC layered, esqueletos; depende de datos reales de v3). |

---

## 📐 Planes de funcionalidad (tracks)

| Documento | Estado | Qué cubre |
|---|---|---|
| [DECENTRALIZED_DISCOVERY.md](DECENTRALIZED_DISCOVERY.md) | ✅ final (E2E pend.) | 3 capas implementadas: PEX gossip + mDNS LAN + bootstrap cache. La estrategia vigente. |
| [DISCOVERY_STRATEGIES.md](DISCOVERY_STRATEGIES.md) | 🔀 brainstorm/backlog | 26 estrategias; ideas vivas (tracker A1, friend-lists, aliases) no implementadas. Elegida: DECENTRALIZED. |
| [OFFLINE_INVISIBILITY_PLAN.md](OFFLINE_INVISIBILITY_PLAN.md) | 📐 plan (2026-06-13) | Que los streams **apagados** no sean descubribles: cierra el residuo Kad de 24 h + auto-deanon del bootstrap (Fase 0), luego descubrimiento sellado por `pubkey` + liveness oculta + cover traffic (Fases 1-2). Capa de descubrimiento de la arquitectura de privacidad. |
| [AUTHENTICATED_TUNNEL_HANDSHAKE_PLAN.md](AUTHENTICATED_TUNNEL_HANDSHAKE_PLAN.md) | 🟢 IMPLEMENTADO dormante (2026-06-14) | Handshake de túnel **autenticado** (CREATE/CREATED v2): firma Ed25519 de nodo + binding de transcript en HKDF. 1+2 saltos picados+compilan; gated dormante (cap sin anunciar → emite v1, cero cambio). Cierra el MITM activo V↔hop2 (rendezvous malicioso) y la degradación. `INodeIdentityStorage` (DPAPI/POSIX, Fase 5-ready). Pendiente runtime. |
| [protocol/AUTH_TUNNEL_3PC_VALIDATION.md](protocol/AUTH_TUNNEL_3PC_VALIDATION.md) | 🧪 receta lista | Validación runtime 3-PC del handshake v2: activación (encender cap), topología V/hop1/hop2, curl exactos (4711), **rogue-relay test** (hop1 altera ev_pub2 → `SIG_FAIL`) + matriz de diagnóstico (rechazo-cripto vs timeout, trazas mutuamente excluyentes). |
| [MOBILE_VIEWER_PLAN.md](MOBILE_VIEWER_PLAN.md) | 📐 M1 hecho (sin validar) | Track M: ver streams en móvil/TV sin carga P2P (el PC es el cerebro). |
| [PART_HASH_THREAD_PLAN.md](PART_HASH_THREAD_PLAN.md) | 📐 H0+H1 hecho (sin validar) | Track H: hashing de partes fuera del hilo UI (mata congelones en picos de velocidad). |
| [SWARM_DVR_PLAN.md](SWARM_DVR_PLAN.md) | 📐 plan (2026-07-03) | **Swarm DVR (track D)**: rebobinar 10-30 min de un directo desde el enjambre, sin servidores. Dos niveles (ring intocado + `CLiveDvrStore` en disco), opcodes 0xB5-0xB8 + cap bit 22 + TUN_OP 0x60-0x62 (reservas verificadas). D1+D2 = MVP local sin wire; D3+ = plano de enjambre subordinado al borde vivo. Post-v9; D0 (reservas) puede aterrizar antes. |
| [CHANNEL_MANIFEST_PLAN.md](CHANNEL_MANIFEST_PLAN.md) | 📐 plan (2026-07-03) | **Canales pubkey estilo YouTube**: manifiesto de canal firmado (ChannelRecord v2 + TLV), catálogo VOD como colecciones firmadas (tags 0x6F-0x72), página de canal + suscripciones + notificación en-directo. TRES secretos (sk_channel ≠ read_secret); privado = sellado, assets jamás por eD2K. Cap bit 23 + TUN 0x24/0x25. C0-C1 local; C5 depende de OFFLINE_INVISIBILITY F0+F1. |
| [V1_UI_MFC_SKELETON.md](V1_UI_MFC_SKELETON.md) | ⏳ pendiente | Spec de 4 tabs MFC (Subscriptions/Browse/MyChannel/Search) para implementación manual. |

---

## 🔬 Auditorías y análisis

| Documento | Estado | Qué cubre |
|---|---|---|
| [SECURITY_AUDIT.md](SECURITY_AUDIT.md) | ♻️ completada (parcial) | Auditoría de `/api/live/*`, HLS (C++ :4711 + Node :8080). XSS legacy FIJOS. **No cubre `/api/live/privacy/*` ni metrics/diagnose/mesh.** |
| [VALIDATION_3PC_EDGE_PUNCTUALITY.md](VALIDATION_3PC_EDGE_PUNCTUALITY.md) | 🧪 diseñada, sin ejecutar | Receta 3-PC para validar el endurecimiento de 3 vectores: puntualidad de borde (①, peer rogue que gana confianza y sabotea el bloque crítico), zero-ts (②) y tuneo /24 (③). Hook de fault-injection `ESE_TEST_HOOKS` + qué contadores API monitorizar + control anti falso-positivo. |
| [PERF_AUDIT.md](PERF_AUDIT.md) | 🔬 en progreso | Revisión perf cpp-a-cpp (~290 .cpp por tiers); estados APLICADO/PENDIENTE/DOC/WONTFIX. |
| [OBJECIONES_Y_RESPUESTAS.md](OBJECIONES_Y_RESPUESTAS.md) | 🔬 adversarial | Objeciones nivel-revisor contra el diseño, con estado: ✅ resuelto / 📐 en plan / ⚠️ abierto / ✗ premisa falsa. |
| [audit/CODE_REVIEW_SCOPE.md](audit/CODE_REVIEW_SCOPE.md) | ⏳ bloqueante V1 | Módulos críticos a revisar antes de V1 (crypto, transport, channels, Kad v2). |
| [audit/REVIEW_LOG.md](audit/REVIEW_LOG.md) | ⏳ 16 módulos pending | Log de revisión de seguridad; V1 gated en todos = PASS. |
| [audit/proverif/README.md](audit/proverif/README.md) · [REVIEW](audit/proverif/REVIEW.md) | ⏳ humano | Modelo ProVerif del handshake 2-hop; escrito, pendiente de ejecutar y firmar. |

---

## 🔄 Compatibilidad, Q&A y checklists

| Documento | Estado | Qué cubre |
|---|---|---|
| [ACCEPTANCE_CHECKLIST.md](ACCEPTANCE_CHECKLIST.md) | ⏳ hardware | Tests que requieren hardware real (cross-GPU/cross-OS sanity). |
| [OBJECIONES_Y_RESPUESTAS.md](OBJECIONES_Y_RESPUESTAS.md) | 🔬 | *(ver Auditorías)* — registro citable de objeciones al diseño. |

---

## 📦 Changelogs

| Documento | Qué cubre |
|---|---|
| [CHANGELOG_v8.0.0_to_v8.1.0.md](CHANGELOG_v8.0.0_to_v8.1.0.md) | Delta v8.0.0→v8.1.0: 32 commits, plano de control anónimo, estabilidad alto bitrate, fragmentación. |
| [CHANGELOG_vanilla0.70b_to_v8.1.0.md](CHANGELOG_vanilla0.70b_to_v8.1.0.md) | Divergencia total vs vanilla 0.70b (~330 ficheros). Núcleo eD2K/Kad/AICH intacto. |

---

## 📦 Release notes

| Documento | Qué cubre |
|---|---|
| [RELEASE_NOTES_v0.70b-eSE8.1.0.md](RELEASE_NOTES_v0.70b-eSE8.1.0.md) | **Actual.** Plano de control anónimo (Sprints A–D), validado 3 PCs a 12000 kbps. Circuitos 1-salto (privacidad plena llega en E). |
| [RELEASE_NOTES_V1_DRAFT.md](RELEASE_NOTES_V1_DRAFT.md) | ⏳ Draft gated: V1 = arquitectura de privacidad (tesis) completa. Bloqueado por revisión ProVerif + 16 módulos PASS. |
| Serie v7.x (15 docs) | [v7.0](RELEASE_NOTES_v0.70b-eSE7.0.md) (P2P Live E2E + discovery descentralizado) → [v7.1](RELEASE_NOTES_v0.70b-eSE7.1.md)…[v7.1.9](RELEASE_NOTES_v0.70b-eSE7.1.9.md) (ciclo rápido de bugfixes) → [v7.2.0](RELEASE_NOTES_v0.70b-eSE7.2.0.md) (gossip dead-stream) → [v7.2.1](RELEASE_NOTES_v0.70b-eSE7.2.1.md) (hotfix). Serie lineal, no paralela. |

---

## 📖 Guía de usuario y recursos

| Documento | Qué cubre |
|---|---|
| [USER_GUIDE.md](USER_GUIDE.md) | Guía end-user: instalar, ver, emitir, troubleshooting. |
| [screenshots/README.md](screenshots/README.md) | Requisitos de las 7 capturas para la guía rápida (placeholder). |

---

## 🗄️ Archivo histórico (`docs/archive/`)

> Completados, decididos o caducados. Se conservan como registro; no son fuente de verdad.
> Índice de la carpeta: [`archive/README.md`](archive/README.md).

| Documento | Por qué |
|---|---|
| [archive/STREAM_BROWSER_PLAN.md](archive/STREAM_BROWSER_PLAN.md) | ✅ hecho (S01/S03/S05; S02/S04 skip). |
| [archive/V8.1_SPRINT_A_BREAKDOWN.md](archive/V8.1_SPRINT_A_BREAKDOWN.md) | ✅ hecho (commit `2c9bfeb`, 2-PC). |
| [archive/V8.1_SPRINT_B_BREAKDOWN.md](archive/V8.1_SPRINT_B_BREAKDOWN.md) | ✅ hecho (commit `6d168da`, 2-PC). |
| [archive/V8.1.1_SPRINT_E_SPEED.md](archive/V8.1.1_SPRINT_E_SPEED.md) | 📋 análisis decidido; spec en E_BREAKDOWN. |
| [archive/DISCOVERY_PLAN.md](archive/DISCOVERY_PLAN.md) | ✅ DISC-S01–S14; S15→V3. |
| [archive/DISTRIBUTION_ANALYSIS.md](archive/DISTRIBUTION_ANALYSIS.md) | 🗄️ snapshot caducado (2026-05-16). |

---

## 🧩 Notas de precedencia y solapamientos (para no confundirse)

- **`MODERNIZATION_ROADMAP.md` vs `MODERNIZATION.md`:** el primero es el plan director (fases,
  ejecución); el segundo es inventario técnico de componentes vetustos. Coexisten; el ROADMAP manda.
- **IPv6:** canónico = `IPV6_PLAN.md`; `IPV6_ANALYSIS` (comparativa) e `IPV6_SPRINT_PLAN` (operativo)
  son satélites. Además vive como Track R (R.4) en el ROADMAP. ~25% implementado.
- **Discovery:** vigente = `DECENTRALIZED_DISCOVERY.md`; `DISCOVERY_STRATEGIES` es brainstorm/backlog;
  `DISCOVERY_PLAN` (hecho) está archivado.
- **Sprint E (E-α/E-β):** `V8.1.1_SPRINT_E_BREAKDOWN.md` es **autoritativo**; `MASTER_PLAN.md` y
  `SPRINTS_V3.md` (RLNC/SRT) son estrella polar, no el alcance real.
- **SPRINTS v2/v3/v4:** escalera de escalabilidad futura, no el trabajo vigente (que es v8.1.x).
- **Tesis ≠ implementación:** `THESIS_KAD_SIN_LOWID` y las tesis en worktrees son diseño calibre v9,
  gated por sus prerrequisitos. No describen lo que el código hace hoy.

---

*Este índice es navegación, no contenido: cada fila apunta al documento que manda sobre su tema.
Al crear un doc nuevo en `docs/`, añade aquí una fila; al archivar uno, muévelo a la sección 🗄️.*
