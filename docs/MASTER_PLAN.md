# eSE Live — Plan Maestro de Escalabilidad y Producto

> Documento vivo. Actualizar a medida que se valide cada hipótesis con
> stress tests reales. Versión inicial: 2026-05-15.

## 0. Resumen ejecutivo

eSE Live es un fork de eMule 0.70b que añade **broadcast en directo P2P**
sobre la red eD2K + Kad. El núcleo P2P funciona end-to-end (PC1→PC2
verificado vía VLC). El reto real es **escalar** sin caer cuando muchos
viewers se conectan a un mismo stream, con la propiedad deseada de que
**más peers = mejor experiencia**, no peor.

Este documento mapea sistemáticamente:
- Qué tenemos hoy (con citas a `archivo:línea`)
- Dónde se rompe a cada nivel de carga
- Cómo debería funcionar al ideal
- Qué trabajo concreto hay que hacer para llegar

**Conclusión upfront**: con la arquitectura actual aguantamos ~10-20
viewers fiables. **El cambio de juego es el principio de contribución
obligatoria** (sección 1bis): cada viewer sube al menos lo que descarga.
Con eso operando, la red gana capacidad linealmente y **50,000 viewers
es alcanzable en P2P puro**, sin CDN ni VPS. Sin contribución obligatoria,
500 viewers ya es imposible.

---

## 1. Visión y criterios de éxito

### 1.1 Qué queremos

Un sistema P2P de live streaming donde:
- **Cualquier usuario** puede emitir desde casa con un click
- **Cualquier usuario** puede ver con un link, sin descargas, sin login
- **Privacidad por defecto**: el viewer no ve la IP del emisor sin opt-in
- **Sin servidor central**: descubrimiento vía Kad, transporte vía eD2K + uTP
- **Sin TOS de terceros**: no Cloudflare, no AWS, no nada que pueda banearnos
- **Network effect**: más viewers conectados = más ancho de banda agregado
  disponible = mejor para todos

### 1.2 Criterios de éxito mensurables

Reescrito tras introducir el principio de contribución obligatoria
(sección 1bis): los tiers de escala se mueven hacia arriba significativamente.

| Eje | v1 (foundation) | v2 (P2P real) | v3 (network effect) | v4 (escala masiva) |
|---|---|---|---|---|
| Viewers fiables por stream | 1-50 | 500-5,000 | 5,000-50,000 | 50,000-500,000 |
| **Modelo forwarding** | chunk-based (HLS) | chunk-based optimizado | **packet-level UDP+FEC** | packet-level + SVC |
| **Latencia broadcaster→viewer** | <15s | <5s | **<2s** | **<1s** |
| % chunks perdidos por viewer | <2% | <0.5% | <0.1% | <0.05% |
| Tiempo a primer frame | <30s | <10s | <5s | <3s |
| Recovery tras churn de upstream | <10s | <3s | **<200ms** (multi-parent) | <100ms |
| Calidad consistente bajo carga | testpattern OK | sin caídas a 500 | sin caídas a 5k | sin caídas a 50k |
| Funciona desde LowID | sí (HighID broadcaster) | sí (cualquier broadcaster) | sí + bypass NAT | leaf-only |
| **Contribución obligatoria** | n/a | ratio 0.7 lax | **ratio 1.0 estricto** | **ratio 1.0 + ABR forced** |
| **Auto super-seeder** | n/a | sí (5-15 leaves) | sí (15-30 leaves) | + mega-seeder (30+) |
| **Tree fanout** | n/a (star) | B=5, D=3 | **B=6, D=5** (12k viewers) | **B=8, D=6** (300k) |
| **Multi-parent** | no (single source) | 2 parents | **3 parents** | 3-5 parents |
| **WebRTC viewers (browser)** | no | no | opcional | recomendado |

### 1.3 Lo que NO intentamos

- **Distribución legal de contenido con copyright**: el sistema es
  agnóstico al contenido; la responsabilidad recae en el broadcaster.
- **Replay / VoD**: solo live. VoD es bittorrent normal, ya existe.
- **Pagos / monetización**: out of scope.

---

## 1bis. EL PRINCIPIO DE CONTRIBUCIÓN OBLIGATORIA

**Esta es la pieza arquitectónica más importante de todo el documento.**

### 1bis.1 Regla absoluta

> **Todo peer sube al menos tanto como descarga.**
> No es opcional. No es opt-in. No es "si quieres".
> Es la condición para participar.

Sin esto, escalar a 500+ es imposible y a 50k+ ridículo. Con esto,
**la red gana capacidad linealmente con los viewers**: cuanta más gente
se conecta, más ancho de banda agregado disponible.

### 1bis.2 Aritmética del network effect

Stream a 3 Mbps:
- **Sin contribución**: el broadcaster necesita N × 3 Mbps de upload.
  Con 1k viewers = 3 Gbps. Imposible desde casa, caro desde VPS.
- **Con contribución 1:1** (cada viewer sube lo que baja):
  - Upload demand global: N × 3 Mbps
  - Upload supply global: N × 3 Mbps (si todos contribuyen)
  - **Equilibrio independiente de N**
  - El broadcaster solo siembra los primeros 5-10 peers; el resto se
    auto-organiza
- **Con contribución 1:1 y 70% de peers contribuyendo** (resto LowID/movil):
  - Supply: 0.7N × 3 Mbps = 2.1N Mbps
  - Demand: N × 3 Mbps
  - Déficit: 0.3N × 3 Mbps cubierto por super-seeders FTTH (que tienen
    20+ Mbps de upload y sirven a 5-7 leaves cada uno)
  - **Sigue funcionando linealmente** porque los super-seeders compensan

### 1bis.3 Auto-promoción a super-seeder (oculto al usuario)

Cada peer al arrancar:
1. Mide su upload sostenido (test corto contra el broadcaster, ~3s)
2. Se auto-clasifica:

| Upload medido | Rol | Sirve a |
|---|---|---|
| < 0.5 × bitrate | **Leaf-restricted** | Solo recibe; rol degradado, calidad reducida (ABR low) |
| 0.5 - 1.5 × bitrate | **Leaf** | Recibe; sirve cuando el ratio cae bajo (uno o ningún viewer) |
| 1.5 - 4 × bitrate | **Mid** | Sirve a 1-3 leaves |
| 4 - 10 × bitrate | **Super-seeder** | Sirve a 5-15 viewers |
| > 10 × bitrate | **Mega-seeder** | Sirve a 20-30 viewers |

3. Anuncia su rol + capacidad disponible vía Kad bajo `livehash:<HASH>`
4. Re-evalúa periódicamente (cada 30s) y se reclasifica si cambia

**El usuario NO ve nada de esto.** La UI solo muestra "watching stream"
o "broadcasting". El motor de mesh decide topología transparentemente.

### 1bis.4 Enforcement del ratio (cómo se obliga)

**Tracking continuo por peer** (en cada cliente):
```
struct PeerRatio {
  uint64 bytes_received_total;     // bytes que YO descargué
  uint64 bytes_sent_total;          // bytes que YO subí
  uint64 bytes_received_window_60s; // últimos 60s
  uint64 bytes_sent_window_60s;     // últimos 60s
  float  ratio_session;             // sent/received cumulative
  float  ratio_recent;              // sent/received últimos 60s
};
```

**Política gradient (no binaria)**:
- `ratio_recent >= 1.0` → recibo a velocidad completa
- `ratio_recent in [0.7, 1.0)` → throttle suave: 80% de velocidad
- `ratio_recent in [0.4, 0.7)` → throttle medio: 50%
- `ratio_recent < 0.4` → throttle agresivo: 20% (degradación visible para forzar contribución)
- `ratio_recent == 0` por >120s → desconexión, mensaje "tu cliente no
  está contribuyendo, verifica firewall/upload"

**Quién lo enforce**:
- Cada peer tracking sus contadores con CADA peer al que sirve
- Si el peer X te da poco a ti, le sirves poco a él
- **Local enforcement**: no necesita servidor central, es bilateral
- Resistente a clientes modificados que mientan: si tu cliente miente
  pero no sube, los peers que lo sirvieron lo notarán y le throttearán

### 1bis.5 Excepciones forzosas (peers que no pueden contribuir)

No todo el mundo puede subir 3 Mbps continuos:
- **LowID con symmetric NAT**: nadie puede conectar A ellos para recibir → solo descarga
- **Móvil con datos limitados**: 100 GB/mes != 24h × 3 Mbps × 60min × 60s = 8 GB/hora = 192 GB/día
- **ADSL <1 Mbps up**: físicamente no puede subir el bitrate

**Solución**: estos peers son **leaf-restricted**:
- Reciben, no sirven
- Reciben SOLO la variante de bitrate más baja (ABR low ~500 kbps)
- Para subir de tier (ej. ABR mid 1500), tendrían que demostrar
  contribución
- Mensaje transparente al usuario: "Estás viendo en calidad reducida
  porque tu conexión no permite contribuir. Cambia a WiFi/red rápida
  para HD"

Este es el equilibrio: **NO excluimos a nadie**, pero el peso se reparte
proporcional a la capacidad. El que más puede, más sirve.

### 1bis.6 Bootstrapping (cómo arranca el sistema)

**Problema del huevo y la gallina**: el primer viewer no tiene a quién
servir; el segundo solo tiene al primero. ¿Cómo aplicas ratio si no hay
nadie a quien subir?

**Solución gradiente**:
- Primeros 5 viewers: ratio_required = 0 (gracia)
- Viewers 5-20: ratio_required crece de 0.0 a 0.7 linealmente
- Viewer 20+: ratio_required = 1.0 estricto

Mientras hay <5 viewers el broadcaster lo absorbe (es el caso normal de
broadcasts pequeños tipo "amigo emite a 3 colegas"). En cuanto hay
masa crítica, el principio se aplica.

### 1bis.7 Implicación para el escalado

Con este principio, las metas de escala se reescriben:

| Tier | Sin contribución obligatoria | Con contribución obligatoria |
|---|---|---|
| 50 viewers | Posible (broadcaster aguanta) | Trivial |
| 500 viewers | Imposible (300 Mbps up imposibles) | Cómodo (50 super-seeders sirven el resto) |
| 5,000 viewers | Imposible | **Alcanzable** con tree formation |
| 50,000 viewers | Imposible | **Alcanzable** con super-seeders + ABR + FEC |
| 500,000 viewers | Imposible | Investigación abierta (DHT no escala así) |

**Conclusión**: 50k era utópico sin este principio, pero **es alcanzable
con él**. 500k sigue siendo investigación, pero NO es porque P2P no
escale; es porque la capa de discovery (Kad) tiene latencia O(log N)
y su replication factor degrada con churn alto.

### 1bis.8 Lo que NO se ve (transparencia)

Toda esta complejidad es **invisible al usuario final**. La UI solo:
- "Watching stream — quality: HD" (o "SD" si está en leaf-restricted)
- "Contribuyendo a la red ✓" (icono pequeño, opcional)
- En modo debug: panel con bytes_in/out, tier, ratio actual

El usuario nunca configura tiers, nunca ve "super-seeder", nunca elige
peers. Solo abre el link y ve. El motor decide todo.

---

## 1ter. EL BROADCASTER LIGERO

**Otro pilar arquitectónico**: el broadcaster doméstico jamás debe servir
a más de 10-20 peers directos. Su carga es CONSTANTE independientemente
de cuántos viewers tenga el stream.

### 1ter.1 Carga del broadcaster

| N viewers totales | Broadcaster sirve a | Upload broadcaster | Por qué |
|---|---|---|---|
| 10 | 10 (todos directos) | 30 Mbps | Sweet spot pequeño |
| 100 | 10 super-seeders | 30 Mbps | Resto via árbol |
| 1.000 | 10 super-seeders | 30 Mbps | Tree fanout=6, D=4 |
| 10.000 | 10 super-seeders | 30 Mbps | Tree fanout=6, D=5 |
| 100.000 | 10 super-seeders | 30 Mbps | Tree fanout=8, D=6 + WebRTC leaves |

**Key insight**: el broadcaster es como una "fuente de televisión".
Solo siembra a los super-seeders. **No debe importarle cuánta gente
hay viendo**. Su carga es 30 Mbps constantes, perfectamente sostenible
desde casa con FTTH simétrica.

### 1ter.2 Implementación

Cuando broadcaster recibe SUBSCRIBE:
1. Si tiene <10 super-seeders activos: acepta, promueve este peer
   a super-seeder si su upload >4× bitrate
2. Si tiene >=10 super-seeders activos: rechaza con `REDIRECT` que
   incluye lista de los 10 super-seeders actuales como candidatos
3. El peer rechazado se conecta a un super-seeder
4. Si todos los super-seeders también están llenos: redirect a mids
5. La cascada continúa hasta llegar a un nodo con capacidad

**El broadcaster NUNCA acepta a un viewer normal directamente**,
salvo durante bootstrap (primeros 10 segundos del stream).

### 1ter.3 Failover de super-seeder

Si un super-seeder cae:
- Sus hijos detectan timeout (chunks no llegan en >2s)
- Inmediatamente promueven al multi-parent secundario que ya tienen
- En paralelo, el broadcaster detecta el hueco (su SS no envía
  HEARTBEATs cada 5s) y selecciona un nuevo super-seeder de los mids
  con mayor upload medido

Tiempo de recovery: <500ms para el viewer (gracias a multi-parent),
<2s para el árbol completo (re-promoción de mid a super-seeder).

### 1ter.4 Ancho de banda agregado escalando

Con este modelo, **la capacidad de la red crece con N**:

```
Capacidad agregada = Σ (upload de cada peer no-leaf)
                   = N_super_seeders × upload_SS
                   + N_mids × upload_mid
                   + N_sub_mids × upload_sub_mid
                   + ...
```

Como cada nivel tiene B veces más nodos que el anterior, y todos
contribuyen su upload, la capacidad agregada **crece exponencialmente**
con la profundidad del árbol.

Demanda agregada = N × bitrate (lineal con N)

**Ratio supply/demand**: con B=6 y FTTH penetration ~70%:
- N=1.000 → supply 18 Gbps, demand 3 Gbps → **6× margen**
- N=10.000 → supply 180 Gbps, demand 30 Gbps → **6× margen**
- N=100.000 → supply 1.8 Tbps, demand 300 Gbps → **6× margen**

El margen es lo que cubre churn, peers lentos, retransmisiones FEC,
etc. Mientras se mantenga >2-3×, el sistema es estable.

---

## 2. Estado actual

### 2.1 Lo que funciona end-to-end (verificado 2026-05-15)

```
┌─ PC1 (HighID) ─────────────────────────────────────────────┐
│  FFmpeg testpattern → seg_NNNNN.ts en %TEMP%\eMule_RTMP\   │
│  RTMPIngest::WatcherLoop → CLiveStreamManager::FeedSegment │
│  CLiveChunkBuffer (ring 16 segs, ~3MB cada uno)            │
│  CLiveKadBridge::PublishStream → Kad publish (eselive +    │
│    title + livehash:HASH)                                   │
│  TCP listen 38362 (eD2K)                                   │
└────────────────────────────────────────────────────────────┘
                            │
                ed2k://|live|HASH|IP:PORT|TITLE|/
                            │
                            ▼
┌─ PC2 (LowID, Kad amarillo) ────────────────────────────────┐
│  EmuleDlg::OnEd2kLink (Ctrl+V) → JoinStream + dial directo │
│  TCP outbound a 88.11.22.161:38362                         │
│  CreateSubscribePacket → broadcaster                       │
│  OnPeerBitmap (oldest=N, bitmap)                           │
│  RequestMissingSegments → CreateRequestPacket              │
│  OnChunkReceived → AddSegment + WriteViewerHlsSegment      │
│  Escribe seg_NNNNN.ts + stream.m3u8 en                     │
│    %TEMP%\eMule_RTMP\<HASH>\                               │
│  VLC → reproduce stream.m3u8 ✓                             │
└────────────────────────────────────────────────────────────┘
```

**Building blocks adicionales que existen pero NO se han probado a escala**:
- `LiveMeshManager` — tracking de N peers, rarest-first, trust levels
- `OnPeerRequest` en viewer — viewers SÍ pueden servir chunks a otros viewers
- Mesh peer-list packet — broadcaster manda hasta 5 IPs de otros viewers
- DDoS rate limit por /24 subnet (50 req/5s)
- Hole-punch LowID-LowID (código existe, sin demostrar)

### 2.2 Test matrix actual

| Test | Resultado | Notas |
|---|---|---|
| Broadcast testpattern | ✅ | 3000 kbps OK, chunks fluyen |
| Broadcast screen capture | ✅ | OK |
| Broadcast RTMP/OBS | ⚠️ no probado con OBS real | FFmpeg listener arranca |
| Broadcast file (mono-audio) | ⚠️ no probado | Watcher fixed para multi-audio |
| Broadcast file (multi-audio) | ⚠️ no probado | Fix aplicado (commit `d73c6ba`) |
| 1 viewer, link directo | ✅ | <5s a primer chunk |
| 1 viewer, link anónimo | ⚠️ inconsistente | Hash-keyword aplicado, falta validar |
| 2+ viewers simultáneos | ❌ NUNCA PROBADO | Lo grande |
| 2 viewers cross-feed (relay) | ❌ NUNCA PROBADO | Crítico para escala |
| Broadcaster restart + viewer reconnect | ❌ NUNCA PROBADO | |
| Viewer cuyo upstream cae (failover) | ❌ NUNCA PROBADO | |

---

## 3. Arquitectura objetivo (escalable)

### 3.1 Principios

1. **Contribución obligatoria** (sección 1bis).
   Todo peer sube al menos lo que descarga. Sin esto no escala. **Pilar #1**.
2. **Broadcaster sirve a O(√N) o O(log N), no O(N)**.
   El broadcaster es el cuello de botella absoluto. Tiene que delegar.
3. **Auto-promoción a super-seeder** según capacidad de upload medida.
   Oculto al usuario. El motor decide.
4. **Cada viewer es también re-emisor** (network effect real).
   Más viewers = más ancho agregado disponible.
5. **Múltiples padres por viewer** (típicamente 3-5 sources).
   Si uno cae, los otros cubren — no pause de stream.
6. **Heterogeneidad de peers** gestionada por ABR + tier.
   Pipes gordas (FTTH) → mega-seeders. Pipes finas (4G/ADSL) →
   leaf-restricted con calidad reducida automáticamente.
7. **Self-healing topology**.
   Churn (entrar/salir) constante es la norma; el árbol se reorganiza solo.
8. **Privacidad-first**.
   Anonymous por defecto (sin IP en link); IP solo se revela peer-a-peer
   bajo subscripción.
9. **Transparencia hacia el usuario**.
   Toda la complejidad del mesh, ratios y tiers es invisible. La UI
   solo muestra "watching" o "broadcasting".

### 3.2 Topología deseada — forwarding tree

**Premisa fuerte**: el broadcaster solo siembra a ~10 super-seeders.
A partir de ahí el árbol fanout-N se replica hacia abajo, alcanzando
miles de viewers con pocos niveles.

```
                  ┌─ Broadcaster (FTTH 30 Mbps up) ─┐
                  │  Sirve a 10 super-seeders       │
                  │  Carga: 10 × 3 Mbps = 30 Mbps   │
                  └─────────────────────────────────┘
                                  │
       ┌──────┬──────┬──────┬─────┼─────┬──────┬──────┬──────┐
       ▼      ▼      ▼      ▼     ▼     ▼      ▼      ▼      ▼   (×10)
  ┌──────────┐
  │SuperSeeder│  FTTH 100+ Mbps up
  │  fanout=6 │  Carga: 6 × 3 = 18 Mbps
  └─────┬─────┘
        │
   ┌────┼────┬────┬────┬────┐
   ▼    ▼    ▼    ▼    ▼    ▼  (×6)
  ┌─────────┐
  │  Mid    │  FTTH 50 Mbps up
  │fanout=6 │  Carga: 6 × 3 = 18 Mbps
  └────┬────┘
       │
   ┌───┴───┬───┬───┬───┬───┐
   ▼   ▼   ▼   ▼   ▼   ▼   (×6)
  ┌─────────┐
  │ Sub-Mid │  Cable/4G 20+ Mbps up
  │fanout=6 │
  └────┬────┘
       │
   (sigue hasta level 5-6)
       │
       ▼
   Leaves (LowID/móvil/ADSL — solo reciben, no sirven)
```

### 3.3 Aritmética del fanout (cuánta gente cabe)

Con branching factor B y profundidad D:
- N_viewers = 10 × B^(D-1)
- Cada nodo intermedio sirve a B viewers, carga = B × bitrate

| B | D=2 | D=3 | D=4 | D=5 | D=6 | Carga por nodo | Quién aguanta |
|---|---|---|---|---|---|---|---|
| 5 | 50 | 250 | 1.250 | 6.250 | 31.250 | 15 Mbps | FTTH 100 Mbps |
| 6 | 60 | 360 | 2.160 | 12.960 | 77.760 | 18 Mbps | FTTH 100 Mbps |
| 8 | 80 | 640 | 5.120 | 40.960 | 327.680 | 24 Mbps | FTTH 300 Mbps |
| 10 | 100 | 1.000 | 10.000 | 100.000 | 1.000.000 | 30 Mbps | FTTH 300+ Mbps |

**Realista (residencial FTTH normal en España, 100-300 Mbps simétrico)**:
- B=6, D=4 → **2.160 viewers** con solo 4 niveles de árbol
- B=6, D=5 → **13.000 viewers**
- B=8, D=5 → **41.000 viewers**

**El broadcaster solo carga 10 super-seeders SIEMPRE**, independientemente
de N total. Su upload constante = 30 Mbps. **Esto sí es escalable** porque
no depende de N.

### 3.4 Latencia: chunk-based vs packet-level forwarding

**Aquí está el problema crítico de profundidad de árbol**:

#### Modelo A — chunk-based (lo que tenemos hoy)
- Peer recibe chunk completo (2s de video, ~750 KB)
- Lo guarda en buffer
- Lo reenvía a sus hijos
- Cada hop añade **al menos 2s** (tiene que esperar a tener el chunk completo)
- Árbol D=5 → +10 segundos de latencia → **NO sirve para "live"**

#### Modelo B — packet-level forwarding (la solución para baja latencia)
- Peer NO espera a tener el chunk completo
- Reenvía bytes del chunk a sus hijos según los va recibiendo
- Cada hop añade ~50-100ms (latencia de red + procesamiento)
- Árbol D=5 → +500ms de latencia → **funciona para "live"**
- Implica: transporte UDP+FEC (no TCP), porque TCP serializa por completitud

**Comparación**:

| Modelo | Latencia D=5 | Resilencia | Complejidad |
|---|---|---|---|
| Chunk-based (HLS-style, hoy) | +10s (inviable) | Alta (TCP retransmit) | Baja |
| Packet-level (UDP+FEC) | +500ms | Media (FEC tolera 5-10% loss) | Alta |
| Híbrido (packet en árbol + chunk en gap recovery) | +500ms cuando todo va bien, +2s en recovery | Alta | Muy alta |

**Recomendación**: hybrid model
- **Live edge**: packet-level UDP forwarding por el árbol — sub-segundo latencia
- **Bootstrap nuevo viewer**: chunk-based pull desde super-seeder — recibe los últimos
  10s en 1-2s para alcanzar al live edge
- **Gap recovery**: si el packet-level pierde un chunk completo, pull TCP a
  cualquier neighbor

### 3.5 Multi-parent obligatorio (resilencia)

Cada peer mantiene **3 conexiones simultáneas**:
1. Parent primario (tree forward main)
2. Parent secundario (warm spare, recibe duplicado, descarta)
3. Parent terciario (en otra rama del árbol, para resiliencia regional)

Si parent #1 cae:
- Parent #2 ya tiene el stream sincronizado → switch en <100ms
- Sin pause visible para el viewer
- Solicita un nuevo parent #3 al tracker (super-seeder o Kad)

**Coste**: cada peer recibe ~1.5× el bitrate (1.0 del primario + 0.5 redundancia
del secundario que descarga selectivamente para mantener fresh el buffer).
Soportable con FEC inteligente (parents diferentes envían FEC parcial).

### 3.6 Diferencias clave con BitTorrent

BitTorrent funciona porque los peers tienen **piezas distintas** del mismo
archivo y pueden intercambiarlas peer-a-peer en cualquier orden. Live es
diferente porque **todos quieren la pieza más nueva al mismo tiempo**.

Soluciones que aplicamos:
- **Forwarding tree, no mesh aleatorio**: estructura jerárquica para asegurar
  que cada peer recibe el live edge con latencia predecible
- **Sliding window de bootstrap**: nuevos viewers no necesariamente al edge —
  pueden empezar 5-10s atrás y irse acercando, evitando saturar al broadcaster
- **Packet-level (no chunk-level)**: latencia constante por hop, no por chunk
- **Multi-parent**: redundancia para tolerar churn sin pausas

### 3.7 Ancho de banda escalando con N (network effect real)

Con la arquitectura propuesta:
- **Demanda total**: N × 3 Mbps
- **Suministro broadcaster**: constante 30 Mbps (solo 10 super-seeders)
- **Suministro super-seeders**: 10 × 18 Mbps = 180 Mbps (cubre 60 mids al edge)
- **Suministro mids cada nivel**: añaden ~B × 3 Mbps por nodo
- **Suministro de leaves**: 0 (no sirven, solo reciben)

Para que el sistema sea SUFICIENTE: en cada nivel, los nodos no-leaf deben
sumar suficiente upload para alimentar al siguiente. Con tree balanceado +
ratio enforcement, esto se cumple. **Cuanta más gente entra, más capacidad
agregada hay**, no menos. Ese es el milagro buscado.

**Excepción**: si entran demasiados leaves (>50% de los viewers), el árbol
no encuentra dónde meterlos sin sobrecargar a los pocos super-seeders.
Solución: **límite de leaves por super-seeder**, y rechazo si la red está
"top-heavy" en peers no-contributors. Mensaje al usuario: "esta emisión
está saturada de leaves, contribuye o espera".

---

## 4. Análisis por componente

### 4.1 Pipeline de ingesta (FFmpeg → chunks)

**Qué es**: produce chunks .ts de 2s desde una fuente (testpattern, screen,
file, RTMP/OBS) y los inserta en `LiveChunkBuffer`.

**Cómo funciona hoy** ([RTMPIngest.cpp](srchybrid/RTMPIngest.cpp)):
- Spawns FFmpeg con args distintos según source mode (Start/StartTestPattern/
  StartScreenCapture/StartMediaFile)
- WatcherLoop polea el dir cada 200ms buscando `seg_NNNNN.ts`
- Lee el .ts a memoria (max 10 MB), llama callback que va a `FeedSegment`
- Watchdog reinicia FFmpeg si muere (excepto en RTMP listen mode)

**Dónde se rompe**:
| Síntoma | Causa | Threshold |
|---|---|---|
| chunks.count se queda en 0 con FFmpeg vivo | Watcher no encuentra archivos (e.g. patrón multi-audio) | Cualquier source con patrón distinto a `seg_NNNNN.ts` |
| Latencia >10s del primer chunk | `Sleep(2000)` antes de empezar a leer | siempre |
| `chunks.count==1 forever` | uint32 underflow en AddSegment (FIXED `7fc806e`) | regresión histórica |
| FFmpeg dies + watchdog loop spam | OBS no conecta a RTMP listener | cuando broadcaster usa RTMP sin OBS pushing |
| Disk fill | `eMule_RTMP\<hash>` subdirs no se borran | después de N broadcasts |

**Cómo debería funcionar al ideal**:
- FFmpeg arranca con `-re` para tiempo real, `-g` GOP corto (1s) para
  decodificación rápida
- Watcher con `ReadDirectoryChangesW` (notificación OS) en vez de polling
- Latencia primer chunk: <2s (vs ~5s actual)
- Cleanup de subdirs en cada Stop
- Patrón de archivo flexible: aceptar `seg_*.ts` con regex

**Qué hay que hacer**:
- [ ] Sustituir polling 200ms por `ReadDirectoryChangesW` async
- [ ] Cleanup `RemoveDirectory` per-stream en `StopBroadcast` y `LeaveStream`
- [ ] Configuración FFmpeg con GOP=1s para reducir latencia HLS
- [ ] Validar patrón regex `^seg_(\d+_)?(\d+)\.ts$` (para multi-audio)
- [ ] Test con OBS real, archivos MP4 mono y multi-audio, screen capture sostenido

### 4.2 Buffer & sliding window

**Qué es**: ring buffer circular de hasta 16 segmentos en memoria del broadcaster
y de cada viewer. Es la estructura de datos central P2P.

**Cómo funciona hoy** ([LiveChunkBuffer.cpp](srchybrid/LiveChunkBuffer.cpp)):
- 16 slots fijos
- AddSegment evicta el más viejo cuando llega el 17º
- HasSegment / GetSegment / GetBitmap consultados por mesh
- Bitmap = 16 bits indicando qué seg [oldest..oldest+15] están en buffer

**Dónde se rompe**:
| Síntoma | Causa | Threshold |
|---|---|---|
| Viewer pide chunk antiguo, broadcaster lo evictó | Ventana de 16 segs = 32s de buffer | viewer >32s atrás del live edge |
| Memoria escala mal por viewer | Cada chunk ~1.5 MB × 16 = 24 MB por stream | <100 MB por broadcast normal |
| Lock contention | `CCriticalSection` global, todas operaciones serializan | >10 viewers concurrentes pidiendo |

**Cómo debería funcionar al ideal**:
- Tamaño de ventana adaptativo según RAM disponible (16-128 segs)
- Lock granular per-segment (RW lock) en vez de global
- Cero-copia: viewer puede compartir buffer del segmento sin memcpy

**Qué hay que hacer**:
- [ ] Constante `ESE_LIVE_MAX_SEGMENTS` configurable vía pref
- [ ] Migrar `CCriticalSection` a `SRWLock` con shared (read) vs exclusive
- [ ] Reference counting de chunks para zero-copy
- [ ] Métrica: ratio de "missed window" peticiones por viewer

### 4.3 Protocolo P2P (paquetes eSE Live sobre eD2K)

**Qué es**: extensión de opcodes de eMule que va por la conexión TCP eD2K
existente. Define paquetes SUBSCRIBE / UNSUBSCRIBE / CHUNK / REQUEST /
HEARTBEAT (bitmap) / PEERLIST / ANNOUNCE / END.

**Cómo funciona hoy** ([LivePackets.cpp](srchybrid/LivePackets.cpp), [LiveProtocol.cpp](srchybrid/LiveProtocol.cpp)):
- OP_LIVE_SUBSCRIBE (0xE0): viewer→peer, "quiero stream HASH"
- OP_LIVE_CHUNK (0xE1): peer→viewer, payload del segmento
- OP_LIVE_REQUEST (0xE2): viewer→peer, "dame seq=N"
- OP_LIVE_HEARTBEAT (0xE3): peer→viewer, bitmap actualizado
- OP_LIVE_PEERLIST (0xE4): broadcaster→viewer, otros viewers conocidos
- OP_LIVE_ANNOUNCE (0xE5): broadcaster→todos, "tengo seq=N nuevo"
- OP_LIVE_END (0xE6): "stream terminó"

**Dónde se rompe**:
| Síntoma | Causa | Threshold |
|---|---|---|
| `kbps=0` en log de viewer | Bitrate no se serializa en CHUNK ([LivePackets.cpp:52](srchybrid/LivePackets.cpp:52)) | siempre |
| Chunks duplicados | Push BOOT-5 + viewer pide los mismos | en cada JoinStream |
| Latencia a viewer aumenta linealmente con N | No hay multicast lógico — ANNOUNCE va 1-a-1 | >50 viewers |
| No hay backpressure | Si peer está saturado, no le decimos que pare | siempre |

**Cómo debería funcionar al ideal**:
- CHUNK packet incluye bitrate + duración exacta + códecs
- ANNOUNCE como evento push a todos los suscritos en paralelo (thread pool)
- Backpressure: peer responde con "throttle me to X kbps"
- Compresión opcional de payload (Zstd) — payload de chunks no se comprime
  bien (ya es .ts H.264 comprimido), pero metadata sí
- Versioning del protocolo: byte mayor/menor para evolucionar sin romper

**Qué hay que hacer**:
- [ ] Añadir bitrate (uint16) y duration_ms (uint16) a OP_LIVE_CHUNK header
- [ ] Bumpear minSize y mantener back-compat con peers viejos
- [ ] Implementar backpressure: campo "want_kbps" en HEARTBEAT
- [ ] Versioning: OP_LIVE_HELLO con version+capabilities exchange

### 4.4 Mesh & topología (LO MÁS IMPORTANTE PARA ESCALA)

**Qué es**: la red de conexiones entre peers que mueve los chunks.

**Cómo funciona hoy** ([LiveMeshManager.cpp](srchybrid/LiveMeshManager.cpp), [LiveStreamManager.cpp:557-694](srchybrid/LiveStreamManager.cpp:557)):
- Broadcaster acepta a TODOS los SUBSCRIBE → broadcastPeers crece sin límite
- Viewer descubre peers vía PEERLIST (5 IPs) que envía broadcaster
- LiveMeshManager target=5 peers, pull rarest-first cada 500ms
- OnPeerRequest sirve chunks desde buffer SIN límite de uploads simultáneos

**Dónde se rompe**:
| Síntoma | Causa | Threshold |
|---|---|---|
| Broadcaster upload satura, lag en chunks | No hay cap, todos pegados al broadcaster | ~15-30 viewers en 10 Mbps up |
| Viewers a varios hops del broadcaster aún piden directo | No hay tree formation; PEERLIST tiene 5 IPs aleatorios | siempre con >50 |
| Peer rápido se satura sirviendo a 30 viewers | No hay cap por peer | siempre con peer en árbol concurrido |
| Peer lento es elegido como source y bloquea | No hay bandwidth-aware selection | random |
| Churn cae el árbol | No hay multi-parent fallback | siempre |

**Cómo debería funcionar al ideal**:

```
JOIN protocol (idea):
  Viewer→Broadcaster: SUBSCRIBE
  Broadcaster: "Estoy lleno (>5 directos), pero esta lista de
    super-seeders te pueden servir: [IP1, IP2, IP3, IP4]"
  Viewer→IP1...4 en paralelo: SUBSCRIBE
  Cada super-seeder responde aceptar/rechazar según su carga
  Viewer mantiene 3-5 conexiones activas (multi-parent)
  Si una cae, las otras cubren

UPLOAD POLICY (cada peer):
  Mido mi upload sostenida (test inicial, refinar online)
  cap_uploads = floor(my_upload_kbps / stream_kbps) - 1
    (- 1 para reserva de mi propio download)
  Acepto SUBSCRIBE hasta cap_uploads
  Si rechazo, devuelvo lista de peers alternativos

REDISTRIBUCIÓN PROACTIVA:
  Cuando recibo un chunk nuevo, lo PUSHEO a todos mis hijos
    sin esperar a que pidan
  Reduce latencia (fan-out paralelo) y carga (no procesar requests)
```

**Qué hay que hacer (ordenado, este es el corazón de v2)**:

- [ ] **S1 [crítico]**: cap configurable de viewers directos al broadcaster
  (default 5). Cuando se rebasa, broadcaster responde SUBSCRIBE con
  "REDIRECT to peers [a,b,c,d,e]".
- [ ] **S4 [crítico]**: cap de uploads simultáneos por peer, basado en
  bandwidth medido. Endpoint en `LiveStreamManager::OnPeerSubscribe` que
  rechace si está saturado.
- [ ] **S2 [arquitectura]**: tree formation algorithm. Peer nuevo NO se
  conecta primero al broadcaster; pregunta a Kad por peers existentes,
  intenta conectarse a 3-5 de ellos. Solo si todos rechazan, va al
  broadcaster.
- [ ] **S6 [arquitectura]**: viewer publica a Kad bajo `livehash:<HASH>` con
  TTL=60s. Eso lo convierte en "fuente conocida" para nuevos viewers.
  Auto-republish cada 30s mientras tenga buffer.
- [ ] **S3 [optimización]**: peer selection basada en bandwidth conocido.
  Trust system actual rastrea bytesServed; usar como proxy de upload.
- [ ] **S7 [resiliencia]**: multi-parent (3-5 sources concurrentes). Si
  uno cae (timeout 5s sin chunks), no pause: los otros llenan.
- [ ] **Push proactivo**: cuando un peer recibe un chunk nuevo, lo pushea
  a sus hijos sin esperar request. Solo pull para gap recovery.

### 4.5 Discovery (Kad)

**Qué es**: cómo se encuentran broadcasters y viewers en la red sin servidor central.

**Cómo funciona hoy** ([LiveKadBridge.cpp](srchybrid/LiveKadBridge.cpp)):
- Broadcaster publica bajo keywords: "eselive", primera-palabra-de-titulo,
  categoría, idioma, y `livehash:<HASH>` (añadido hoy en `d73c6ba`)
- Viewer busca por keyword → recibe lista de (streamKey, IP, port)
- TryConnectToStreamSource dialea directo

**Dónde se rompe**:
| Síntoma | Causa | Threshold |
|---|---|---|
| Anon link no descubre stream en <30s | Propagación Kad lenta / nodos diferentes | flaky siempre |
| Viewers no encuentran a otros viewers | Solo broadcaster publica a Kad | siempre |
| Kad search cooldown bloquea reintentos | 5s/30s cooldown | después del primer intento |

**Cómo debería funcionar al ideal**:
- Broadcaster + cada peer con buffer publican `livehash:<HASH>` → red
  llena de fuentes
- Viewer busca por hash → recibe 50+ candidates → conecta a los 5 más cercanos
- DHT bootstrap caché local: nodes.dat actualizada continuamente

**Qué hay que hacer**:
- [ ] Viewer publish a Kad bajo `livehash:<HASH>` cuando count buffer >5
- [ ] Auto-republish cada 30s mientras conectado al stream
- [ ] Reducir cooldown inicial: 5s primer intento, exponencial después
- [ ] Trace logs por SearchID para ver tiempo a primer resultado

### 4.6 NAT / Conectividad (hole-punch)

**Qué es**: cómo dos LowID (ambos detrás de NAT) consiguen establecer una
conexión directa P2P.

**Cómo funciona hoy** ([BaseClient.cpp:1492-1518](srchybrid/BaseClient.cpp:1492), [KademliaUDPListener.cpp:2070-2236](srchybrid/kademlia/net/KademliaUDPListener.cpp:2070)):
- LowID viewer trying HighID broadcaster: TCP outbound funciona, no necesita HP
- LowID-LowID: SendEseHolePunchReq via Kad UDP, simultáneo open
- ACK confirma pinhole, luego uTP (libutp) sobre el mismo UDP
- 4 reintentos antes de declarar symmetric NAT

**Dónde se rompe**:
| Síntoma | Causa | Threshold |
|---|---|---|
| Symmetric NAT rejection | Heurística simple (4 attempts) | ~10-20% NATs domésticos |
| uTP setup falla tras pinhole | Race en libutp, no validado | desconocido (nunca probado) |
| Hole-punch encrypted vs plaintext fallback | Lógica existe, no validada | desconocido |

**Cómo debería funcionar al ideal**:
- STUN classification al arrancar para detectar tipo de NAT (full cone /
  restricted / port restricted / symmetric)
- Si symmetric: NO intentar HP, ir directo a TURN-relay (super-seeder
  voluntario o broadcaster como relay)
- Telemetría real: ratio HP success / attempts por país/ISP

**Qué hay que hacer**:
- [ ] **B1 (de auditoría)**: test end-to-end real con dos LowID + telemetría
  de bytes_after_punch
- [ ] STUN classification al arranque (hay libs Open Source pequeñas)
- [ ] Métrica de HP success rate por subnet visible en `/api/holepunch/stats`

### 4.7 Capa Web (Node.js + C++ WebServer)

**Qué es**: dos HTTP servers en localhost que sirven UI + API.
- Node.js eSE en :8080 — dashboard, player, /live, /debug
- C++ WebServer en :4711 — endpoints `/api/live/*` con acceso a estado interno

**Cómo funciona hoy**:
- Node.js spawn automático al arrancar emule.exe (`ToggleEseServer(false)` en `EmuleDlg.cpp:672`)
- Browser hace fetch al Node, Node proxy a 4711 cuando necesita estado C++
- Comunicación por HTTP (no IPC nativa, no WebSocket)

**Dónde se rompe**:
| Síntoma | Causa | Threshold |
|---|---|---|
| RCE captura pantalla LAN | `/api/live/*` sin auth (FIXED `f0c17b4`) | mitigado a localhost-only |
| WebServer del C++ no bindea | Pref `Enabled=false` en portable (FIXED `d73c6ba`) | mitigado |
| Polling cada 2-3s desde browser | Node hace HTTP a C++ → carga | >10 viewers concurrentes |
| Latencia de updates (chunks count) | Polling 2s vs realidad | UX se siente lenta |

**Cómo debería funcionar al ideal**:
- Una sola capa HTTP (probablemente Node como front, C++ vía pipe nombrada o socket Unix)
- WebSocket bidireccional para updates de estado en realtime
- Auth con token compartido C++ ↔ Node (ahora son dos islas)

**Qué hay que hacer**:
- [ ] Eventualmente unificar: WebSocket entre Node y C++ con shared token
- [ ] SSE en `/api/live/log` para tail en realtime sin polling
- [ ] Decidir si seguimos con dos HTTP layers o consolidamos

### 4.8 Player & playback (HLS.js)

**Qué es**: el navegador del viewer reproduce el stream.m3u8 que se va
escribiendo en disco según llegan chunks.

**Cómo funciona hoy** ([live_tv_page.js + channel_api.js /live/watch/HASH](srchybrid/eSE/eSE-live/channel_api.js)):
- HLS.js fetcha `/hls-local/HASH/stream.m3u8` (sirviendo por Node desde disco)
- Polling de `/api/live/debug` cada 3s para overlay status
- Player hace play() en MANIFEST_PARSED, transición a PLAYING en FRAG_BUFFERED

**Dónde se rompe**:
| Síntoma | Causa | Threshold |
|---|---|---|
| "Buscando en Kad" infinito | Polling /api/live/debug falla, HLS.js NO carga (no chunks) | cuando WebServer C++ down |
| Buffer underrun → pause | Chunks llegan tarde | latencia de red elevada |
| Bitrate fijo, sin adaptación | Solo 1 variant en m3u8 | siempre |

**Cómo debería funcionar al ideal**:
- ABR multi-bitrate: variants 500/1500/3000 kbps
- HLS.js auto-selecciona según bandwidth medido
- Overlay diagnóstico que distingue "eMule offline" / "stream offline" / "buffering"
- Latencia low-latency-HLS (chunks de 1s, partial segments)

**Qué hay que hacer (no urgente para v1)**:
- [ ] **D4**: overlay branchea por `d.error === 'offline'` vs no chunks
- [ ] **B5 (v2)**: producir 2-3 variants en FFmpeg (`-var_stream_map`)
- [ ] LL-HLS support (chunks de 1s, partial segments) — reduce latencia 5x

### 4.9 Seguridad

**Cómo funciona hoy**:
- Node `security.js` con bearer token + cookie + rate limit
- C++ WebServer ahora localhost-only en `/api/live/*` (commit `f0c17b4`)
- Stream key (16 bytes random) actúa como "auth" implícita: solo quien tiene el link puede ver
- IPFilter de eMule clásico (lista de IPs baneadas)

**Riesgos abiertos**:
| Riesgo | Severidad | Mitigación necesaria |
|---|---|---|
| Acceso remoto al WebServer C++ requiere desactivar el guard | Bajo (intencional) | Doc + endpoint `/api/admin/enable_remote` con password |
| Stream key 128 bits = adivinar imposible, pero quien obtiene el link entra | Por diseño (privacidad anonymous) | Optional invite-only mode con clave compartida adicional |
| Anti-leech inexistente | Alto a escala | S8 (rate limit por peer + ratio enforcement) |
| DDoS al broadcaster (peticiones masivas) | Medio | Rate limit por /24 ya existe, refinar por viewer en mesh |

**Qué hay que hacer (a futuro)**:
- [ ] Auth token compartido C++ ↔ Node para permitir acceso remoto seguro
- [ ] Optional "private stream" mode: cifrar chunks con AES, key se distribuye fuera de Kad
- [ ] Anti-leech: peer que recibe X bytes pero no sirve nada se le throttle el download

### 4.10 Observabilidad

**Cómo funciona hoy**:
- `CLiveDebugLog` ring buffer 500 líneas, visible en MFC tab + `/api/live/log` + `/debug` page
- Counters en `m_counters`: chunksReceived, chunksRequested, chunksMissing, kadPublishes, etc.
- `/api/live/debug` JSON con snapshot completo

**Dónde falla para escala**:
- Ring de 500 líneas se llena en segundos con N viewers
- No hay agregación: solo eventos individuales
- No hay export a sistema externo (Prometheus, etc.)

**Cómo debería funcionar al ideal**:
- Métricas agregadas separadas de eventos discretos
- Histogramas: latencia chunk arrival (p50, p95, p99)
- Métricas por peer: bytes in/out, RTT, % chunks served vs requested
- Export Prometheus opcional

**Qué hay que hacer**:
- [ ] **S9**: estructura `MeshMetrics` con histograma sliding window
- [ ] Endpoint `/api/live/metrics` con formato Prometheus
- [ ] Persistencia opcional de log a disco (rotated file)

---

## 5. La historia del escalado

Cómo se rompe (y cómo lo arreglamos) a cada nivel de N viewers.

### 5.1 N=1 (HECHO ✅)

Funciona end-to-end. Verificado con VLC.

### 5.2 N=5-50 viewers — "primera prueba real"

**Lo que funciona**: la mayoría conecta directo al broadcaster. Si broadcaster
tiene >10 Mbps up, aguanta.

**Lo que se rompe primero**:
- Broadcaster CPU subiendo (cada CHUNK packet al socket)
- Lock contention en `m_lock` (todos los OnPeerRequest serializan)
- Latencia chunks aumenta linealmente con N (sin multicast lógico)
- Nuevos viewers que entran piden seg=0 (broadcaster ya lo evictó) → bootstrap roto

**Trabajo necesario para llegar aquí fiable**:
1. **S1** cap viewers/broadcaster (default 10) — los rechazados van a peers
2. **A2** locks granulares (RW por peer)
3. **S9** métricas reales para SABER dónde duele
4. Bootstrap correcto: viewer entra, primer chunk = `oldestSeq` actual no 0

### 5.3 N=50-500 viewers — "P2P real"

**Cuello de botella**: el broadcaster ya no puede.

**Lo que se rompe**:
- Si todos van directo → upload broadcaster muere a los 30s
- Sin tree formation, los redirigidos no encuentran a otros viewers
- Sin multi-parent, churn de un peer = pause de 5-15s para sus hijos
- Peers heterogéneos: el más lento es el cuello de botella

**Trabajo necesario**:
1. **S2** tree formation (broadcaster redirige a super-seeders)
2. **S6** viewer publica a Kad como source
3. **S7** multi-parent (3-5 sources concurrentes)
4. **S3** bandwidth-aware peer selection
5. **S4** cap uploads por peer
6. Push proactivo: peer empuja chunks a hijos sin esperar request

### 5.4 N=500-5000 viewers — "necesita ABR"

**Cuello de botella**: heterogeneidad de peers. Móvil 4G no aguanta 3 Mbps.

**Trabajo necesario**:
1. **S5** ABR multi-bitrate (500/1500/3000)
2. Cada bitrate tiene su propio mesh (los de 500 kbps comparten entre sí)
3. Broadcaster produce 3 variants — más CPU, pero indispensable
4. **S8** anti-leech / fairness para que peers gordos sigan compartiendo

### 5.5 N=5000-50000 viewers — "el network effect de verdad"

Con el **principio de contribución obligatoria** (sección 1bis), este tier
es alcanzable en P2P puro, sin VPS y sin CDN.

**Aritmética con contribución 1:1 + super-seeders auto**:
- 50,000 viewers, 70% contribuyen 3 Mbps each = 105 Gbps de upload agregado
- Demand: 50,000 × 3 Mbps = 150 Gbps
- Déficit: 45 Gbps cubierto por mega-seeders (FTTH 100+ Mbps × 1500 nodos)
- Realista en mercados con FTTH masivo (España, Francia, Corea, Japón)

**Lo que SÍ se necesita en este tier**:
- ABR multi-bitrate operando (peers de movil sirven solo low-quality)
- FEC para tolerar 5-10% packet loss sin retransmit
- Geographic peer selection (RTT < 50ms preferido)
- Heartbeat cada 200ms en vez de 2s (necesario para sub-1s failover)
- Métricas distribuidas (cada peer reporta health a un agregador opt-in)

**Lo que se rompe en este tier**:
- **Discovery**: Kad propagation tarda 30s, mal para nuevos viewers en
  pico. Necesita gossip/seed-nodes a partir de cierta densidad
- **Churn**: 50k viewers con 5%/min churn = 2500 join/leave por minuto.
  El árbol no se reorganiza tan rápido sin algoritmo eficiente
- **Coordinación**: ningún peer ve más que sus N vecinos directos.
  Decisiones globales (ej. "este es el live edge") requieren consenso

**Trabajo necesario**:
- Gossip-based discovery overlay sobre Kad (usar Kad para arranque,
  luego peer-to-peer announce)
- Optimizar churn handling: pre-establecer multi-parent (5+ sources) para
  que la caída de uno sea recuperación local, no re-tree global
- ABR con SVC (capas) para que cambiar variant no requiera re-buffer

### 5.6 N>100k — "investigación abierta"

A este tier, los problemas dejan de ser de bandwidth (la red ya tiene
de sobra con contribución obligatoria) y se vuelven de **coordinación**:
- DHT (Kad) no escala bien a millones de keys con TTL bajo
- Latencia de propagación es problema fundamental
- Probablemente requiere protocolo de gossip optimizado para live (BetterMix, Plumtree, Hyparview)
- WebRTC para viewers en navegador (sin instalar nada) — multiplica audiencia 10×

**Honest opinion**: a partir de 50k viewers, el problema deja de ser
técnico y se vuelve "**cómo monetizas la infraestructura**" o "**cómo
incentivas a los super-seeders**". Soluciones:
- Modelo Wikipedia: donación voluntaria de upload (lo que ya hacemos)
- Modelo BitTorrent: ratio enforcement estricto (lo de sección 1bis)
- Modelo crypto: token económico (Theta-like, complejidad regulatoria)
- Modelo híbrido: P2P core + super-relays opcionales (VPS opt-in)

Para 100k+ realista sin enredar legales: combinación de los dos
primeros (lo que ya estamos diseñando) escala hasta donde alcance la
red de FTTH. En España con 80%+ de FTTH disponible, **100k en horario
peak es factible**.

---

## 6. Modos de fallo por nivel de carga

| Nivel | Primer fallo | Manifestación | Fix |
|---|---|---|---|
| 1 viewer | (ninguno hoy) | — | — |
| 5 viewers | Lock contention | Latencia chunks +500ms | RW lock per chunk |
| 10-20 viewers | Broadcaster CPU | Drops esporádicos | S1 cap |
| 30 viewers | Broadcaster upload | Buffer underflow en viewers | S1 + S2 |
| 50 viewers | PEERLIST con 5 IPs | Mesh sigue centralizado en broadcaster | S6 viewer-publish |
| 100 viewers | Sin tree formation | Star topology, broadcaster muere | S2 + S3 |
| 200 viewers | Heterogeneidad | Peers móvil cortan, fragmentan árbol | S5 ABR |
| 500 viewers | Churn rate | Re-tree constante, latencia variable | S7 multi-parent + churn handling |
| 1000+ | Discovery (Kad latency) | Nuevos viewers tardan 30s+ | DHT optimizado o seed nodes |
| 5000+ | Bandwidth agregado limitado | Quality drops cascada | Híbrido con relays |

---

## 7. Roadmap

### Fase 1 — v1: "funciona con 1-50 viewers" (~30h)

**Funcionalidad** (sin estos no se puede usar):
- B3 — discovery `/api/live/kad/streams` → `addRemoteChannel()`
- D2 — MFC link directo además del anónimo
- D3 — unificar 3 entry points viewer
- D4 — overlay honesto offline vs no-stream

**Estabilidad**:
- A1 — bitrate en CHUNK packet
- A2 — race Join/Leave
- A3 — cleanup subdirs
- Métricas básicas (S9 nivel 1)

**Onboarding**:
- D1 — saltarse wizard clásico en portable
- B7 — UPnP toggle en wizard

**Validation**:
- Test exhaustivo con OBS real
- Test con archivo MP4 single + multi audio
- Test con 5 viewers reales (no fake)

### Fase 2 — v2: "P2P real con contribución obligatoria, 500-5000 viewers" (~3-6 meses)

**El pilar arquitectónico es 1bis (contribución obligatoria)**, NO un anti-leech
añadido tarde. Todo el diseño se construye asumiéndolo desde el principio.

**Orden de ejecución (estricto, cada paso desbloquea el siguiente)**:

1. **S9 métricas reales** (~1 semana)
   - Counters por peer: bytes_in/out, ratio, latencia chunk
   - Endpoint `/api/live/metrics` formato Prometheus
   - Histogramas de p50/p95/p99 de latencia
   - **Sin esto navegamos a ciegas. Bloquea todo lo demás.**

2. **S10 stress test simulator** (~1-2 semanas)
   - Modo headless de eMule (`--headless --viewer=HASH`)
   - Orquestador que lanza N procesos
   - Dashboard que muestra dónde se rompe a N=10, 50, 100
   - **Sin esto, los pasos siguientes son guesswork**

3. **Contribución obligatoria base** (1bis.4) (~2-3 semanas)
   - PeerRatio tracking bilateral por conexión
   - Gradient throttle: ratio < 0.7 → reduce velocidad de descarga
   - Mensaje al usuario cuando ratio < 0.4
   - Bootstrap gracia para primeros 5 viewers (1bis.6)

4. **Auto-clasificación de tier** (1bis.3) (~1 semana)
   - Bandwidth test inicial al conectarse
   - Auto-tier: leaf-restricted / leaf / mid / super-seeder / mega-seeder
   - Anuncio del rol vía Kad bajo `livehash:<HASH>`
   - Re-evaluación periódica

5. **S1 + S4 caps configurables** (~3 días)
   - Cap viewers/broadcaster (default 5)
   - Cap uploads/peer según tier auto-clasificado
   - Redirect: cuando lleno, "conecta a estos peers en su lugar"

6. **S6 viewer-publish a Kad** (~1 semana)
   - Cualquier peer con buffer >5 segs se publica como fuente
   - TTL=60s, re-publish cada 30s
   - Discovery de viewers→viewer (no solo broadcaster→viewer)

7. **S2 tree formation** (~2-3 semanas)
   - Algoritmo: peer nuevo consulta Kad por sources, intenta los 5 más
     cercanos primero, broadcaster solo como último recurso
   - El broadcaster RECHAZA SUBSCRIBE si está al cap, con redirect

8. **S3 bandwidth-aware peer selection** (~1 semana)
   - PeerTrust extendido con bandwidth medido
   - Seleccionar el peer con mejor (bandwidth × proximidad) para cada chunk

9. **S7 multi-parent + failover** (~2 semanas)
   - Viewer mantiene 3-5 conexiones activas simultáneas
   - Si un upstream cae (timeout 5s), los demás cubren sin pausa
   - Push proactivo desde cada parent en paralelo

10. **B1 LowID-LowID hole-punch validation** (~1-2 semanas)
    - Test real con dos LowID en NATs distintos
    - STUN classification al arranque
    - Telemetría success rate por país/ISP

**Quality** (paralelo, no bloquea lo de arriba):
- **S5 ABR multi-bitrate** (~2-3 semanas)
  - FFmpeg `-var_stream_map` con 3 variants: 500/1500/3000 kbps
  - HLS.js auto-selecciona en función de bandwidth medido
  - Leaf-restricted siempre en variant low
- LL-HLS (chunks de 1s, partial segments)
- FEC ligero (Reed-Solomon a nivel chunk) para tolerar 5-10% packet loss

### Fase 3 — v3: "packet-level forwarding + tree, 5000-50000 viewers" (~6-12 meses)

**Esta fase es el rewrite del transport layer**. El modelo chunk-based
de v2 funciona pero la latencia que añade cada hop (2s) hace inviable
árboles profundos. Para llegar a miles de viewers con latencia <2s
hay que pasar a packet-level forwarding.

**Trabajo grande, ordenado**:

1. **Packet-level transport con UDP + FEC** (~6-8 semanas)
   - Diseño nuevo: cada chunk se trocea en N paquetes UDP fijos (~1.4 KB MTU-safe)
   - Reed-Solomon FEC a nivel chunk: 10 paquetes datos + 2 paquetes redundancia,
     tolera pérdida de 2/12 sin retransmit
   - Reuso de la conexión uTP existente (libutp ya está integrado)
   - Coexistencia con TCP eD2K para backup/recovery

2. **Forwarding inmediato (no buffer-then-send)** (~3-4 semanas)
   - Peer recibe paquete, lo reenvía a sus N hijos en el mismo tick
   - Latencia añadida por hop: 50-100ms (vs 2s del chunk-based)
   - Tree D=5 → +500ms total — viable para "live"

3. **Tree formation deterministic** (~1 mes)
   - Algoritmo de tree-build: cuando peer entra, descubre la posición
     óptima en el árbol consultando a super-seeders
   - Branching factor B=6 por defecto, configurable según bandwidth medido
   - Re-balance automático ante churn (no rebuild completo, solo local)

4. **Multi-parent obligatorio (3 conexiones)** (~3-4 semanas)
   - Primario: tree main, recibe stream completo
   - Secundario: warm spare en otra rama, recibe FEC de respaldo
   - Terciario: para failover regional / geográfico
   - Switch primary→secundario en <100ms si timeout (bytes/sec)

5. **Gossip-based discovery overlay** (~1-2 meses)
   - Sobre Kad para arranque inicial (hash → 5-10 super-seeders)
   - Después gossip directo entre peers (cada peer comparte 5 vecinos)
   - Reduce latencia de discovery de 30s a <2s para joins en pico

6. **Geographic peer selection** (~3 semanas)
   - Cada peer estima RTT a candidates
   - Preferir peers <50ms RTT (mismo país/región)
   - Tree formation prefiere parents geográficamente cercanos

7. **Métricas globales agregadas** (~3-4 semanas)
   - Peers reportan health a un agregador opt-in (anónimo)
   - Dashboard global: viewers conectados, salud media, mapa
     geográfico, latencia P95 por región
   - Útil para detectar problemas a escala antes que los usuarios

8. **Optimización del protocolo P2P** (~1 mes)
   - Binary diff de bitmaps para HEARTBEAT
   - Multiplex de varios streams sobre la misma conexión
   - Compresión Zstd de metadata (no payload)

### Fase 4 — v4: "escala masiva, 50k-500k" (12+ meses, investigación)

**Solo si v3 demuestra que llegamos a 50k consistentemente**:

1. **WebRTC para viewers en navegador** — multiplica audiencia 10×
   sin barrera de instalar emule.exe
2. **SVC (Scalable Video Coding)** — capas que se combinan, peer
   elige qué capas descargar sin re-encoding
3. **Super-trackers federados** — varios "super-nodos" coordinan
   discovery a escala, federados entre sí
4. **CDN opcional como fallback** — para los primeros segundos del
   primer viewer hasta que el mesh se forma. NO como vía principal.
5. **Posible: micro-incentivos económicos** — si la red lo demanda,
   pero abre Pandora's box regulatorio. Honestamente: evitar mientras
   se pueda.

---

## 8. Preguntas abiertas / investigación

Cosas que NO tienen una respuesta clara y necesitan exploración:

1. **¿Qué pasa con peers a través de symmetric NAT?**
   Hole-punch falla en ~10-20% de los casos. ¿Aceptamos que esos solo
   sean leaves (download-only) o intentamos relay vía un peer no-NAT?

2. **¿Cómo medimos honestamente "calidad" del stream?**
   Métricas obvias: % chunks perdidos, buffer underrun count, tiempo
   pause acumulado. ¿Suma de cuál pondera más?

3. **¿Cuál es el tradeoff exacto latencia vs capacidad de relay?**
   Cuanto más buffer (sliding window) mantenemos, más capaces somos
   de servir a peers en distintas posiciones del live edge. Pero más
   latencia para el viewer. Necesita medición.

4. **¿Vale la pena WebRTC para viewers en navegador?**
   Sin instalar emule.exe, viewers participarían en el mesh desde
   browser. Reduciría barrera de entrada masivamente. Pero WebRTC
   requiere STUN/TURN servers (signaling server posible vía Kad).
   Esfuerzo: 1-2 meses, dependencia: librería WebRTC en C++.

5. **¿Qué hacer con broadcasters LowID?**
   Hoy nuestro flow asume broadcaster HighID. LowID broadcaster
   necesitaría que sus viewers le hagan hole-punch. Posible pero
   no probado.

6. **¿Cuál es la latencia mínima aceptable para "live"?**
   Twitch: 2-5s. YouTube Live: 5-30s. Nosotros: 5-20s estimado.
   Para chat-driven content (gaming) <5s es crítico. Para deportes
   en directo 5-10s OK. Para emisiones tipo radio, no importa.

7. **¿Funcionará Kad como discovery a 10k+ broadcasters concurrentes?**
   Kad fue diseñada para file sharing (millones de keys, propagación
   tolera horas). Para live (TTL bajo, alta frecuencia) puede no
   escalar. Alternativas: gossip protocol custom, super-trackers.

---

## 9. Stress test simulator (S10)

El elemento más importante que falta. Sin esto, todo lo demás es teoría.

### 9.1 Qué necesita

- **Modo headless de eMule**: arrancar sin GUI con flag `--headless --viewer=HASH:IP:PORT --metrics-port=N`
- **Orquestador**: lanza N procesos eMule headless en una o varias máquinas
- **Métricas en JSON** por instancia: chunks recibidos, latencia, peers
- **Dashboard agregador**: muestra distribución vs N

### 9.2 Versiones progresivas

**v0.1** — N=10 viewers en 1 PC (10 procesos eMule headless con configs distintos)
**v0.2** — N=50 viewers en 1 PC con docker (cada container es 1 viewer)
**v0.3** — N=200 viewers en 5 PCs LAN
**v0.4** — N=500-1000 con VMs en cloud (DigitalOcean droplets baratas)
**v1.0** — N=5000+ con kubernetes + métricas distribuidas

### 9.3 Métricas que captura por viewer

- timestamp_join (ms desde wall clock)
- time_to_first_chunk (ms)
- chunks_received_count
- chunks_missed_count
- bytes_received_total
- bytes_uploaded_total
- mean_chunk_arrival_jitter (ms)
- p99_chunk_arrival_jitter (ms)
- peer_disconnect_count
- pause_seconds_total

### 9.4 Reportes que produce

- Distribución de time_to_first_chunk vs N
- Heatmap chunks_missed por viewer en eje X = time, Y = viewer_id
- Bandwidth agregado del broadcaster vs N
- "Health score" agregado: % viewers con <1% loss + <5s pause

---

## 10. Anexos

### A. Citas a código

- Pipeline ingesta: [RTMPIngest.cpp](../srchybrid/RTMPIngest.cpp)
- Buffer chunks: [LiveChunkBuffer.cpp](../srchybrid/LiveChunkBuffer.cpp)
- Protocolo P2P: [LivePackets.cpp](../srchybrid/LivePackets.cpp), [LiveProtocol.cpp](../srchybrid/LiveProtocol.cpp)
- Mesh: [LiveMeshManager.cpp](../srchybrid/LiveMeshManager.cpp), [LiveStreamManager.cpp:557-694](../srchybrid/LiveStreamManager.cpp:557)
- Kad bridge: [LiveKadBridge.cpp](../srchybrid/LiveKadBridge.cpp)
- Hole-punch: [BaseClient.cpp:1492-1518](../srchybrid/BaseClient.cpp:1492), [KademliaUDPListener.cpp:2070-2236](../srchybrid/kademlia/net/KademliaUDPListener.cpp:2070)
- WebServer: [WebServer.cpp:_ProcessLiveAPI](../srchybrid/WebServer.cpp), [WebSocket.cpp](../srchybrid/WebSocket.cpp)
- Player web: [eSE/eSE-live/channel_api.js:1034-1273](../srchybrid/eSE/eSE-live/channel_api.js:1034)
- Debug log: [LiveDebugLog.cpp](../srchybrid/LiveDebugLog.cpp)

### B. Proyectos similares (qué hicieron y por qué fracasaron o triunfaron)

- **BitTorrent Live** (Bram Cohen, 2013-2016) — fracasó. Latencia alta
  por consenso DHT, sin tracción. Cerrado.
- **PeerTube** — federado tipo ActivityPub. Funciona para VoD, su modo
  live es servidor central por canal (no P2P real entre viewers).
- **Theta Network** — P2P + crypto incentives. Funcional pero requiere
  super-nodos pagados; económicamente sesgado.
- **WebTorrent + WebRTC** — funciona excelente para VoD (BitChute,
  Internet Archive). Live es problema abierto.
- **Twitch / YouTube Live / Kick** — CDN puro, no P2P. Coste prohibitivo.
- **Nostr live streaming** — protocolo de relays, no P2P real.

### C. Referencias técnicas

- "P2P Live Streaming: Quality Comparison" — IEEE 2014
- BitTorrent Live whitepaper (archive.org)
- WebRTC: trickle ICE, simulcast, SVC
- HLS Low-Latency spec (Apple, 2020): partial segments + push
- libutp source: NAT traversal patterns
- Kademlia paper (Maymounkov & Mazières, 2002)

### D. Glosario

---

## 11. Investigación profunda (consolidado de 4 informes)

Sección añadida 2026-05-15 tras research deep-dive en 4 ejes paralelos:
- Estado del arte P2P live (qué llegó a 100k+ en producción)
- Latencia / transporte / FEC / codecs
- Topología, churn, descubrimiento a escala
- NAT / WebRTC / browser viewers

Esta sección **resuelve contradicciones** entre los 4 informes y consolida
**decisiones de diseño** con su evidencia. La fuente principal de cada decisión
está citada.

### 11.1 Síntesis ejecutiva (lo que cambia respecto a v0)

Antes de la investigación pensábamos: "single tree con fanout 6-8, contribución
obligatoria por ratio enforcement, packet-level forwarding sobre UDP custom".

**Lo que la investigación nos dice**:

| Pregunta | Respuesta v0 (antes) | Respuesta investigación |
|---|---|---|
| Topología | Single tree | **Hybrid tree+mesh**: árbol con 3 warm spares + mesh fallback obligatorio |
| Contribución obligatoria | Ratio enforcement + auto-tier | **SplitStream-style structural** (cada peer interior en 1/k stripes) MÁS ratio enforcement |
| Transport | UDP custom + FEC | **SRT** (libsrt 1.5.4 MIT, diseñado exactamente para esto) |
| FEC | RaptorQ | **Sliding-window RLNC sobre GF(2^8) + ISA-L** (RaptorQ tiene patentes Qualcomm) |
| Discovery | Pure Kad | **Híbrido: tracker HTTPS + Plumtree/HyParView** (Kad como fallback, no primario) |
| WebRTC browser viewers | "futuro v4" | **v3 — embed libdatachannel** (10× audiencia, ROI altísimo) |
| Latencia objetivo | <2s en v3 | **<2s alcanzable con SRT + cut-through + 5 hops max** |
| 50k+ viewers en P2P puro | "alcanzable con FTTH" | **EMPÍRICAMENTE INEXPLORADO** — nadie ha hecho esto en producción |
| Mobile peers | Leaf restricted ABR low | **Leaf-only forzoso** (asimetría + battery + background) |
| IPv6 | No mencionado | **CRÍTICO**: free HighID a ~50% de Europa, "biggest free win" |

### 11.2 Sistemas que SÍ alcanzaron 100k+ en producción

Lista completa con cifras verificables (no marketing):

| Sistema | Año | Pico verificado | Arquitectura | Lección |
|---|---|---|---|---|
| **PPLive** | 2005-14 | 100k+ por canal | Tracker + mesh + buffer maps + neighbor referral | ISP locality 88% bytes mismo ISP |
| **CoolStreaming/DONet** | 2004-08 | 80k+ | Mesh data-driven + buffer maps + rarest-first | Pure mesh ≠ tree; resilencia bajo churn |
| **LiveSky** (CDN+P2P) | 2009+ | 145k @ 400 kbps | Mesh + CDN fallback con timeout | Híbrido es lo que ESCALA |
| **Peer5** (Microsoft) | 2014+ | hundreds of thousands | HLS+WebRTC mesh + CDN deadline | 90-99% CDN offload at peak |
| **GridMedia** | 2005-09 | 15.239 concurrent (CCTV) | Mesh push/pull hybrid | Push-after-pull es el patrón |
| BitTorrent Live | 2008-17 | nunca a producción | 12 "clubs" deterministicos | Fracaso comercial, no técnico |
| **libp2p gossipsub** | 2018+ | hundreds of thousands (Filecoin) | HyParView + Plumtree | Pero son MENSAJES PEQUEÑOS, no video |

**Insight crucial**: la única arquitectura que ha llegado a 100k+ en video es
**híbrida CDN-P2P con WebRTC mesh** (Peer5/Novage style). Pure-P2P a 100k+
viewers de video **no existe en producción demostrada**.

Implicación: nuestro objetivo de 50k+ es **empíricamente inexplorado** en
P2P puro. Tenemos dos caminos:
1. **Aceptar el híbrido**: super-seeders FTTH actúan como CDN-equivalent (es
   lo que ya proponíamos en sección 1ter — el broadcaster ligero con 10
   super-seeders ES funcionalmente un mini-CDN P2P)
2. **Investigar territorio nuevo**: P2P puro a 50k+, sabiendo que nadie ha
   demostrado que se pueda. Riesgo alto, recompensa alta.

**Recomendación**: camino 1, pero diseñado para que el camino 2 sea posible
si la práctica lo demuestra. Cada super-seeder es un peer voluntario, no
infraestructura paga — eso preserva el espíritu P2P puro.

### 11.3 Decisiones de arquitectura consolidadas

#### 11.3.1 Topología: Tree con warm spares + Mesh fallback

**Contradicción resuelta**: Magharei et al. (INFOCOM 2007) demuestra que
mesh > multi-tree bajo churn, pero BitTorrent Live, Peer5, fybrrStream
todos shipean **single tree with warm spares**. La razón: SplitStream forest
es académicamente bello pero tiene 3 problemas en producción:
- MDC overhead 15-40% bitrate
- DHT lookup latency hurts startup
- Anycast repair no le gana a un warm spare pre-establecido

**Decisión final**: 
- **Single forwarding tree** con cada peer manteniendo **3 warm-spare parents** (heartbeats 1Hz, listos para promote en <500ms)
- **Mesh fallback always-on** para gap recovery (estilo PPLive/CoolStreaming buffer maps)
- **Anycast spare-capacity pattern de SplitStream** para repair cuando los 3 warm spares también caen
- **NO multi-stripe forest** (demasiado complejo, no probado en producción)

#### 11.3.2 Contribución / network effect

**Decisión final**:
- **Auto-tier classification** al arrancar (medir upload, clasificar leaf/mid/super-seeder/mega)
- **Ratio enforcement bilateral**: cada peer trackea bytes_in/bytes_out con cada peer al que sirve, throttle gradient cuando ratio < 0.8
- **Bootstrap gradient**: primeros 5 viewers gratis, ratio_required crece hasta 1.0 en viewer 20+
- **Mobile = leaf-only forzoso** por asimetría + battery + background

**Aritmética verificada por literatura**:
- Sustainable: u_avg / R ≥ 1.2 (sino metaestable)
- Comfortable: u_avg / R ≥ 1.5 (30% headroom para flash crowds)
- Para 2 Mbps stream: **15-20% de peers debe ser FTTH-tier**
- Para 6 Mbps stream: **25-35% FTTH** (España con FTTH masivo lo cubre)
- Free riders: 30-50% de peers sin enforcement → mata la red

#### 11.3.3 Transport layer: SRT

**Decisión final**: **libsrt 1.5.4** (Haivision, MIT, github.com/Haivision/srt)
para la live path. Mantener TCP eD2K para control plane y bulk transfer.

Razones:
- Diseñado exactamente para esto (sub-second contribution)
- `SRTO_LATENCY` window configurable: dentro = ARQ, fuera = FEC
- Maduro, MIT, ampliamente adoptado (broadcasters profesionales)
- Mejor que QUIC para video por enforcement de playback clock
- Mejor que libutp/LEDBAT (LEDBAT yields, opuesto a live)

**NO usar**: TCP (HoL blocking mata árbol depth=5), QUIC (válido pero SRT más maduro), WebRTC media (heavy stack, pero SÍ usar WebRTC datachannels para browser bridge)

Per-hop budget propuesto: 250ms × 5 hops = 1.25s. Total budget 1.75s con safety 250ms sobre target 2s.

#### 11.3.4 FEC: sliding-window RLNC

**Decisión final**: **sliding-window RLNC sobre GF(2^8)** implementado encima
de **Intel ISA-L** (BSD-3, SIMD primitives). ~1500 LOC C++ wrapper.

Razones:
- Block FEC añade 1s solo para llenar el bloque (incompatible con nuestro budget)
- RaptorQ tiene patentes Qualcomm hasta ~2030 (riesgo legal en distribución abierta)
- OpenRQ es solo Java
- Steinwurf Kodo es comercial
- RLNC sobre GF(2^8) es matemáticamente claro y libre de patents

**Config inicial**: ventana 32 paquetes (~50ms de video a 5 Mbps con 1300-byte payloads), repair ratio 1.3× (30% redundancia).

#### 11.3.5 Codec encoding (broadcaster)

**Decisión final**: **libx264 con `-tune zerolatency`** + parámetros específicos:
```
-c:v libx264 -preset veryfast -tune zerolatency
-profile:v baseline -level 4.0
-x264-params "nal-hrd=cbr:keyint=60:min-keyint=60:scenecut=0:bframes=0:rc-lookahead=0:sync-lookahead=0:sliced-threads=1:intra-refresh=1:vbv-maxrate=4000:vbv-bufsize=1000:force-cfr=1"
-g 60 -bf 0
```

Claves:
- `intra-refresh=1` elimina spike de keyframe
- `bf=0` (no B-frames) ahorra 1 frame de latencia por consecutivo
- `vbv-bufsize 250ms` cap encoder buffering
- GOP=60 (2s @ 30fps) compromiso latencia/eficiencia

**Para v4 evaluar**: AV1 LL profiles, LCEVC enhancement layer, SVC para ABR.
Hoy no son maduros para nuestro caso.

#### 11.3.6 Forwarding: cut-through packet-level

**Decisión final**: **packet-level immediate forwarding**, identificado por
`(stream_id, packet_seq)`. Cada peer reenvía bytes según los recibe, sin
esperar al chunk completo.

Razones:
- Chunk-based: D=5 = +10 segundos de latencia (inviable)
- Cut-through: cada hop añade 50-100ms (vs 2s)
- Misma técnica que switching L2 cut-through
- FEC + small repair window cubre la fiabilidad

#### 11.3.7 Discovery: hybrid tracker + Plumtree

**Decisión final**:
1. **Bootstrap**: HTTPS tracker (centralizado, geo-aware, instant convergence)
2. **Membership**: HyParView (active view ~5 peers, passive ~30, sobrevive 80%+ failures)
3. **Stream propagation**: Plumtree (epidemic broadcast tree, sub-second 5 hops a 10k nodos)
4. **Kad como fallback** si tracker está caído (ya lo tenemos, no toca tirarlo)

Razones:
- Pure Kad: 20s bootstrap + 5-15s lookup latency bajo churn — incompatible con live
- libp2p gossipsub (Plumtree+HyParView) está en producción a hundreds of thousands de nodos en Filecoin/Ethereum
- Tracker + DHT híbrido es lo que TODA producción usa

#### 11.3.8 NAT: IPv6 + miniupnpc + relay fallback

**Decisión final**, en orden de leverage:
1. **IPv6 awareness everywhere** (free HighID a 50% Europa, mayor ROI absoluto)
2. **miniupnpc al startup** (PCP+NAT-PMP+UPnP-IGD, ya MIT, recoge LowIDs de "casa normal")
3. **Birthday-paradox UDP hole-punching** (lift de 80% a 92-95% success)
4. **DERP-style always-on relay** (Tailscale pattern: relay primero, upgrade a directo cuando funciona)
5. **TURN fallback** para hard×hard NAT (10-15% inevitable, voluntary super-nodes o $50-300/mo VPS)

Realistic % peers que pueden servir:
- DE/FR/IN (alto IPv6 + FTTH residencial): **60-70%**
- US sin CGNAT: 40-55%
- Mobile-heavy: 15-25%
- **Promedio global ponderado: 40-50%**

#### 11.3.9 WebRTC para browser viewers

**Decisión final**: **embed libdatachannel** (paullouisageneau, MPL-2.0,
~50k LOC C++) en eSE-Server.exe + **datachannel-wasm** en browser.

Razones:
- API espejo entre C++ y browser (un mental model)
- 10× audiencia (viewers en navegador sin instalar)
- Cost engineering: 2-4 person-months
- Binary size: +3-5 MB
- ROI altísimo

NO usar: libwebrtc (Google, mil millones de LOC, build nightmare), Pion (Go GC hurts media perf vs C++).

Para SFU si llegamos a v4: mediasoup C++/Node o LiveKit Go.

### 11.4 Algoritmos concretos a implementar

10 técnicas con paper de origen, listas para integrar:

| # | Técnica | Origen | Aplicación en nuestro sistema |
|---|---|---|---|
| 1 | **Push-after-pull** | GridMedia ACM MM 2005 | Pull primeros 2-3 chunks; cuando peer cumple SLA, promote a push |
| 2 | **Buffer-map exchange (60 chunks ventana, 1Hz)** | CoolStreaming INFOCOM 2005 | Scheduler base mesh fallback |
| 3 | **Neighbor referral peer selection** | PPLive 2009 | ISP locality natural sin tracker overhead |
| 4 | **Multi-parent FEC (4+2)** | Multisource FEC 2014 | Sweet spot demostrado, >8 desperdicia |
| 5 | **PPSPP signed Munro hashes** | RFC 7574 | Stream integrity vs malicious peers |
| 6 | **Slot-based admission flash crowd** | Liu et al. IPTPS 2009 | Reduce interrupciones >60% en lanzamientos |
| 7 | **Skip-on-deadline** | BitTorrent Live patent | No bloquear, FEC cubre |
| 8 | **Stable-peer scoring** | Distilling Superior Peers 2009 | Top quartile uptime → interior nodes |
| 9 | **Anycast spare-capacity group** | SplitStream SOSP 2003 | Repair cuando warm spares también caen |
| 10 | **HyParView+Plumtree gossip** | Leitão DSN/SRDS 2007 | Membership + stream propagation |

### 11.5 Bibliotecas concretas (ready to integrate)

| Componente | Librería | Licencia | Notas |
|---|---|---|---|
| Transport live | **libsrt 1.5.4** | MIT | Haivision, producción broadcasters |
| FEC SIMD | **Intel ISA-L** | BSD-3 | gf_vect_mul para GF(2^8) |
| WebRTC C++ | **libdatachannel** + libjuice | MPL-2.0 + MIT | paullouisageneau, ~50k LOC |
| WebRTC browser | **datachannel-wasm** | MPL-2.0 | API espejo a libdatachannel |
| UPnP/PCP/NAT-PMP | **miniupnpc** | MIT | ya conocido por eMule |
| ICE/STUN/TURN | **libnice** | LGPL | si embebemos full ICE |
| HLS player browser | **hls.js 1.5+** | MIT | LL-HLS support |
| TURN server | **coturn** | BSD | self-hosted $50-300/mo VPS |
| SFU (v4 si crece) | **mediasoup** | ISC | producción WebRTC |

### 11.6 Decisiones honestas y problemas abiertos

**Lo que SÍ vamos a hacer y SÍ se ha demostrado**:
- Tree + warm spares + mesh fallback (3 sistemas en producción)
- IPv6 + miniupnpc (free wins)
- libdatachannel para browser bridge (proven path)
- SRT transport (broadcasters lo usan a diario)
- Sliding-window RLNC (matemáticamente sólido, libre de patents)

**Lo que vamos a INTENTAR pero es exploratorio**:
- 50k+ viewers en P2P puro: **nadie ha llegado**
- Cut-through packet-level con SRT en árbol depth-5: **suena bien, no probado a esa escala**
- Auto-tier classification 100% transparente al user: **conceptual, falta engineering**
- Network effect linealmente con N: **PPLive/CoolStreaming demostraron a 30-100k, queremos extender a 50k+**

**Lo que NO se puede solucionar técnicamente**:
- **Mobile contribution**: bloqueado por carriers + OS + battery (no es problema técnico)
- **Hard×hard NAT**: requiere TURN relay siempre (matemáticamente irresoluble)
- **Sub-2s startup en P2P puro**: solo híbrido CDN-P2P lo logra
- **Long-tail channels (<100 viewers)**: sin masa crítica el sistema colapsa
- **Tit-for-tat para live**: no hay "future trade", incentivos económicos abiertos

### 11.7 SLAs propuestos para v3 (50k viewers)

Targets que se pueden defender técnicamente:

| Métrica | p50 | p95 | p99 |
|---|---|---|---|
| Startup (join → first frame) | 3s | 8s | 15s |
| End-to-end latency live edge | 1.8s | 3s | 5s |
| Recovery tras parent failure | 500ms | 2s | 5s |
| % chunks perdidos | 0% (FEC cubre 5-10% loss) | 0.1% | 0.5% |
| Re-buffering events / minuto | 0 | 0.1 | 1 |

p99 SLAs son **honestos**, no marketing. Viewer detrás de doble cellular hop o región mal conectada va a sufrir, no se puede salvar con código.

### 11.8 Roadmap revisado tras investigación

**Fase 2 (v2): 500-5000 viewers, ~3 meses**
- Mantiene la mayoría del plan original
- Añadir IPv6 awareness desde el inicio
- Añadir miniupnpc al startup
- Build stress test simulator
- Implementar auto-tier classification + ratio enforcement
- Tree con 3 warm spares + mesh fallback

**Fase 3 (v3): 5000-50000 viewers, ~6-9 meses**
- Switch transport: SRT
- Add cut-through packet-level forwarding
- Add sliding-window RLNC FEC
- Add HyParView+Plumtree para membership/propagation
- Add WebRTC bridge: embed libdatachannel + datachannel-wasm
- Add DERP-style relay fallback
- Implementar anycast spare-capacity (SplitStream pattern)

**Fase 4 (v4): 50000+ viewers, exploratorio**
- SVC layered encoding
- SFU super-relays opt-in (mediasoup)
- Geographic-aware peer selection
- Métricas globales agregadas
- LL-HLS para reducir latencia 5x más

### 11.9 Documento de referencias completo

Las referencias están consolidadas en los 4 informes individuales en
`docs/research/` (a crear cuando empecemos a implementar). Las más
críticas:

**Papers fundamentales**:
- Castro et al. SOSP 2003 — SplitStream
- Zhang et al. INFOCOM 2005 — CoolStreaming/DONet
- Magharei et al. INFOCOM 2007 — Mesh vs Multi-Tree comparison
- Leitão et al. DSN/SRDS 2007 — HyParView + Plumtree
- Liu et al. IPTPS 2009 — Flash crowds
- Castro et al. SOSP 2003 — SplitStream anycast

**RFCs**:
- RFC 7574 — PPSPP (Peer-to-Peer Streaming Peer Protocol)
- RFC 6330 — RaptorQ FEC (referencia, no implementar por patents)
- RFC 6887 — PCP (Port Control Protocol)
- RFC 8445 — ICE
- RFC 8680 — FEC sliding window framework

**Proyectos open source clave**:
- libsrt (Haivision) — github.com/Haivision/srt
- libdatachannel (paullouisageneau) — github.com/paullouisageneau/libdatachannel
- miniupnpc — miniupnp.tuxfamily.org
- ISA-L (Intel) — github.com/intel/isa-l
- mediasoup — mediasoup.org
- libp2p gossipsub — github.com/libp2p/specs/tree/master/pubsub/gossipsub
- coturn — github.com/coturn/coturn

**Sistemas de referencia (lo que sí funcionó)**:
- PPLive (legacy) — measurement papers de Hei et al.
- CoolStreaming — papers de Zhang/Liu
- Peer5 / Novage P2P-Media-Loader — github.com/Novage/p2p-media-loader
- BitTorrent Live (US Patent 20150326657A1) — diseño documentado
- Tailscale (NAT traversal patterns) — tailscale.com/blog

---

## 12. ¿Estará "blindado y nunca se cae"? La verdad honesta

**No.** Ningún sistema software lo está. Cualquiera que afirme lo contrario
miente. Esta sección define honestamente qué nivel de resiliencia es
alcanzable, qué amenazas el plan cubre, cuáles no, y cuáles son
**matemáticamente irresolubles**.

### 12.1 Marco: definir "no se cae" y "blindado" sin engañarnos

**Disponibilidad real de servicios "industriales"**:

| Sistema | SLA público | Realidad medida |
|---|---|---|
| AWS S3 | 99.9% | Cae varias veces al año |
| Twitch | sin SLA público | Cae periódicamente, peor en peak (Sub-tember) |
| YouTube Live | sin SLA público | Outages de 30-60min cada pocos meses |
| Cloudflare | 99.99% | Outage global Jul 2024 (40min), Jun 2022 (1h) |
| Microsoft Teams | 99.99% (Enterprise) | Multiples outages 2024-25, 4-8h cada uno |

**Conclusión**: ni los gigantes con miles de ingenieros y miles de millones
de inversión consiguen "nunca se cae". Lo que consiguen es:
1. **Detectar fallos rápido** (segundos)
2. **Degradar con gracia** (servicio reducido, no muerte total)
3. **Recuperarse sin intervención humana** (mayoría de los casos)
4. **Postmortems públicos** y mejoras iterativas

Para nuestro sistema P2P el objetivo realista es:
- **No outage por fallo del broadcaster solo** (si el broadcaster sigue vivo)
- **Degradación gradual** (no freeze de stream cuando un peer cae)
- **Recovery <2s p99** ante cualquier failure de un peer
- **Resilencia ante ataques comunes** (DDoS, pollution, free-riders)
- **Identificable cuando algo va mal** (observabilidad)

NO podemos prometer:
- Zero downtime ever
- Invulnerabilidad ante ataques nation-state
- Supervivencia ante coordinated ISP blocking
- Resistencia a takedowns legales
- Privacidad absoluta de viewers/broadcasters

### 12.2 Amenazas que el plan SÍ cubre bien

| Amenaza | Cómo la cubrimos | Sección/Commit |
|---|---|---|
| **DDoS al broadcaster** | Broadcaster ligero (solo 10 SS) + rate limit /24 + super-seeders absorben carga | 1ter, F.4 commit |
| **Pollution attack** (peer envía chunks corruptos) | PPSPP signed Munro hashes (RFC 7574) | 11.4 #5 |
| **Free-riders** | Auto-tier + ratio enforcement gradient | 1bis.4 |
| **RCE captura pantalla LAN** | Gate localhost-only en /api/live/* | Commit `f0c17b4` |
| **Subscribe flood** | Cap viewers/peer + redirect cascade | 11.3.1 |
| **Single point of failure (broadcaster)** | Multi-parent (3 warm spares) + mesh fallback + anycast spare-capacity | 11.3.1 |
| **Network partition** | HyParView sobrevive 80%+ failures + Kad fallback | 11.3.7 |
| **Resource exhaustion (memoria)** | Ring buffer fijo 16-128 segs + drop on overflow | 4.2 |
| **Stream key prediction** | 128-bit MD4 hash random — adivinar imposible (2^127 combinations) | 2.1 |
| **NAT type abuse** | STUN classification + matching inteligente | 11.3.8 |
| **Log spam attack** | Ring buffer 500 líneas auto-evict | 4.10 |
| **Malicious tracker** | Hybrid (HTTPS tracker + DHT fallback + Kad) — varios independientes | 11.3.7 |

### 12.3 Amenazas que el plan NO cubre (y por qué)

#### 12.3.1 Ataques que requerirían trabajo adicional

| Amenaza | Por qué no la cubrimos | Solución posible |
|---|---|---|
| **Sybil attack** (atacante crea N peers falsos para manipular tree) | Sin sistema de reputación robusto | Proof-of-Work al join, o reputación basada en uptime histórico (~1 mes engineering) |
| **Eclipse attack** (peer rodeado de peers maliciosos coordinados) | Sin diversidad forzada en peer selection | Forzar peer selection desde N AS / N países diferentes (~2 sem engineering) |
| **Censorship attack** (super-seeders coordinados niegan servir cierta key) | Sin detección de censura coordinada | Multi-source obligatorio (ya en plan), monitor de % broadcasts servidos vs publicados |
| **Targeted DDoS al broadcaster** (atacante consigue su IP y la satura desde botnet) | Inevitable si IP queda expuesta | Solo: link anónimo (broadcaster IP no aparece) + super-seeders como buffer |
| **Malicious super-seeder** (relay correcto pero registra metadata: quién ve qué) | Confianza implícita en super-seeders | Encryption end-to-end stream key + viewer-side anonymity con Tor-like routing (3-6 meses) |
| **Coordinated metadata harvesting** (atacante con muchos peers falsos mapea quién ve qué) | P2P inherentemente expone IPs a peers | NO HAY solución técnica completa. Mitigaciones parciales: onion routing (latencia 10x), mixnet (latencia 100x) |
| **Supply chain** (libsrt/libdatachannel/libutp comprometida en upstream) | Confiamos en deps de terceros | Pinned versions, signed releases verification, reproducible builds (~1 mes setup) |

#### 12.3.2 Lo que es MATEMÁTICAMENTE imposible

Estas no se solucionan con código, son leyes de la física o la lógica:

1. **Hard-NAT × Hard-NAT sin relay**: birthday paradox da 0.01% éxito incluso tras 20s de probing. El plan asume 10-15% de peers necesitarán relay TURN siempre. **No hay workaround técnico**.

2. **Anonimato perfecto en P2P**: para que dos peers se comuniquen, AL MENOS uno conoce la IP del otro. P2P es estructuralmente incompatible con anonimato fuerte sin overhead masivo (Tor: 10× latencia, mixnets: 100×).

3. **DDoS L3/L4 al broadcaster doméstico**: si tu IP queda expuesta y un atacante tiene 100 Gbps de botnet, tu conexión cae. Solo solución: que tu IP no quede expuesta. Si emites desde casa con HighID, tu IP es pública por definición.

4. **Long-tail channels viables (<100 viewers)**: P2P necesita masa crítica. Sin viewers no hay peers. Sin peers no hay redistribución. Sin redistribución, broadcaster solo. **No hay ley física que rompa esto**.

5. **DRM compatibility**: ningún content owner aceptará distribuir contenido premium en P2P porque la "última milla" siempre puede grabar. Esto está fuera de scope porque hicimos el sistema agnóstico al contenido (responsabilidad del broadcaster).

6. **Latencia <500ms broadcaster→viewer en árbol depth-5+**: serialización de paquete + RTT × 5 hops. Speed-of-light setea floor. Solo se reduce con menos hops (= menos viewers).

#### 12.3.3 Lo que es problema operacional, no técnico

Cosas que solucionamos solo con compromiso/recursos, no con código:

| Problema | Naturaleza | Coste |
|---|---|---|
| Mantener 2-3 servidores TURN para fallback NAT | Operacional | $50-300/mo VPS + 5h/sem mantenimiento |
| Bug fixes / security patches reactivos | Operacional | Desarrollador disponible permanente |
| Postmortems / incident response | Operacional | Procesos + on-call |
| Soporte usuarios | Operacional | Foro, FAQ, Discord, etc. |
| Compliance regulatoria (GDPR, DMCA) | Legal | Asesoría legal periódica |
| Comunidad / governance | Social | Tiempo de personas |

### 12.4 Failure modes y nuestra respuesta planificada

| Modo de fallo | Probabilidad | Impacto sin plan | Con plan |
|---|---|---|---|
| Broadcaster crash / network down | Media | Stream muerto | Stream muerto (no hay solución sin recording) |
| Super-seeder dropout | Alta (5-10%/min) | 1/N viewers afectados | Warm spare promote, recovery <500ms |
| Peer churn masivo (end of show) | Garantizado | Cascade rebuild, todos afectados | HyParView sobrevive, anycast repair, gradient |
| Bug en update nuevo | Alta (siempre) | Crash en producción | Rolling deploy + observabilidad para detectar |
| ISP block del puerto 4662 | Media (paises restrictivos) | LowID forzoso | UPnP fallback + relay TURN + IPv6 alternativo |
| Memory leak en sesión larga | Posible | OOM crash a las X horas | Métricas de RSS por hora + alertas |
| Disco lleno (subdir leak) | Media | Disco se llena | A3 fix + cleanup periódico |
| ZIP corrupto en distribución | Posible | Usuario no arranca | Signed releases + checksum verification |
| Broadcaster pierde conectividad | Alta | Stream pause hasta reconnect | Reconnect logic + viewer side ride-out 30s |

### 12.5 SLAs realistas comparables a sistemas existentes

Lo que **podemos** prometer si implementamos el plan completo:

| Métrica | Nuestro target | Comparable a |
|---|---|---|
| Disponibilidad agregada (% tiempo "stream visible") | 99.5% | Twitch normal day, peor que YouTube |
| Recovery tras parent failure | <2s p99 | Mejor que CDN tradicional (5-30s) |
| Tolerancia a churn 10%/min | Sin freezes >2s | Igual que PPLive en su época |
| Tiempo a primer frame | <8s p95 | Peor que Twitch (3-5s), igual que CoolStreaming |
| Latencia broadcaster→viewer | 1.8s p50, 5s p99 | Igual que SRT contribution standard |
| Resistencia a DDoS broadcaster | Sobrevive 1 Gbps | Peor que Cloudflare ($200/mo Pro), mejor que router doméstico |
| % chunks perdidos | <0.5% p95 | Igual que IPTV broadcast |

Lo que **no** podemos prometer:
- 99.9% (3 nines) — requiere más redundancia que la que diseñamos
- 99.99% (4 nines) — requiere duplicación geográfica + monitoreo 24/7
- Resistencia a state-actor DDoS — requiere CDN profesional anycast
- Cero pérdida de chunks — físicamente imposible sobre internet sin retransmisión inmediata (rompe latencia)

### 12.6 Roadmap de hardening (5 fases)

Si después de v3 quisieras ir a un nivel adicional de hardening:

**Fase H1 — Hardening básico (2-3 semanas)**
- Rate limit per peer (no solo por /24)
- Memory bounds en TODA estructura (max chunks, max peers, max requests)
- Timeout en TODA operación de red (no operación que pueda colgar)
- Reproducible builds + signed releases
- CI con sanitizers (ASAN, UBSAN, TSAN)
- Code coverage + fuzz testing de protocol parsers

**Fase H2 — Sybil/Eclipse defense (1-2 meses)**
- Sistema de reputación basado en uptime + bytes contributed
- Forzar diversidad de peer selection (al menos N AS / N países)
- Whitelist de super-seeders (gobernanza ligera)
- Detector de patrones de eclipse (peers nuevos del mismo /24 = sospechoso)

**Fase H3 — Privacy hardening (3-6 meses)**
- Encryption end-to-end de payload (no solo transport TLS)
- Optional onion-style routing para viewers que quieren anonimato (3 hops, 3-5x latency)
- Stream key como JWT con scopes (lectura solo, lectura+contribución, etc.)

**Fase H4 — Operacional 24/7 (continuo)**
- Métricas globales agregadas opt-in con dashboards
- On-call / paging cuando degradación detectada
- Comunidad de bug bounty
- Auditoría de seguridad anual independiente
- Compliance con GDPR para viewers EU

**Fase H5 — Escala enterprise (12+ meses)**
- Multi-region super-seeder pools con failover automático
- DDoS protection L3/L4 con BGP anycast (requiere AS propio o partners)
- 99.99% SLA target con duplicación de TODO el stack

### 12.7 La verdad sobre P2P y privacidad

P2P es **fundamentalmente menos privado que CDN**:
- Cada peer del mesh ve la IP de todos los peers a los que sirve / de los que recibe
- Atacante con N peers falsos ve quién ve qué stream
- Broadcaster ve IPs de los super-seeders
- Super-seeders ven IPs de sus children

**Mitigaciones parciales en el plan**:
- Anonymous link (link no expone IP del broadcaster)
- Stream key opacao (no contiene metadatos del broadcaster)
- Localhost-only API (eMule's WebServer no expone /api/live/* a LAN)

**Lo que NO mitigamos**:
- Pasive surveillance: ISP / state actor que mira el tráfico ve emisor + viewer + bitrate
- Active surveillance: atacante con muchos peers correlaciona quién ve qué

**Para anonimato fuerte habría que**:
- Routing onion (Tor-like): 3 hops de relay con encryption en capas, 10× latencia
- Mixnets: enviar paquetes en lotes con delays aleatorios, 100× latencia
- Cover traffic: peers envían tráfico falso constante, 5-10× bandwidth

Ninguna de estas es compatible con "live streaming a baja latencia" en el
estado actual de la investigación.

### 12.8 Diagnóstico realista del estado v0 (hoy)

Ahora mismo (commit `1d806ee`), nuestro sistema:

✅ Tiene mitigaciones para:
- DDoS básico al broadcaster (rate limit /24)
- RCE captura pantalla LAN (localhost-only)
- Free-riders en gran medida (estructura ya inclina a contribución)
- Privacy default (anonymous link, no expone IP)
- Pollution básica (chunks tienen hash chequeado en eD2K)

❌ NO tiene mitigaciones para:
- Sybil / Eclipse (sin reputación)
- DDoS L3 al broadcaster (si IP expuesta)
- Memory leaks no detectados (sin métricas RSS)
- Bugs de protocolo no descubiertos (sin fuzz testing)
- Coordinated metadata harvesting (P2P limitation)
- Disco lleno por subdirs (A3 abierto)

⚠️ Está EN INVESTIGACIÓN si llegará a:
- 50k+ viewers (empíricamente inexplorado)
- Latencia sub-2s a 50k viewers (no demostrado)
- Network effect linealmente con N (PPLive lo logró a 30-100k, no a 50k+)

### 12.9 Respuesta directa a la pregunta

> "¿Si ponemos todo en marcha, queda preparado para el futuro? Para que no caiga nada nunca y blindado contra ataques?"

**No queda "que no caiga nunca y blindado"**, porque eso no existe en software. Pero quedará:

1. **Operacionalmente comparable a Twitch en sus mejores días**: 99.5% disponibilidad, recovery sub-2s, degradación graceful.
2. **Resistente a ataques comunes**: DDoS básico, pollution, free-riders, RCE LAN, sybil moderado (con H2).
3. **Honestamente vulnerable a**: ataques coordinados de N peers maliciosos, DDoS L3 al broadcaster doméstico, deanonymization de viewers, supply chain.
4. **Empíricamente inexplorado a 50k+**: ningún competidor ha demostrado P2P puro a esa escala con video.
5. **Operacionalmente costoso de mantener**: 5-10h/semana de developer disponible para fixes, monitoreo, y respuesta.

**Lo que SÍ podemos garantizar**:
- Cada decisión está justificada por evidencia (papers, sistemas en producción)
- Cada vulnerabilidad conocida está documentada (esta sección)
- Cada SLA es honesto (sección 12.5)
- El sistema degrada en vez de morir (warm spares, mesh fallback, anycast)
- Los problemas se detectan rápido (observabilidad)
- Las amenazas evolucionan, y nosotros también podemos (roadmap H1-H5)

Hardening es **proceso continuo**, no estado final. Twitch tiene equipos
enteros dedicados a security 24/7 y aún tiene incidentes. Nosotros con
una persona y AI podemos llegar a un nivel de calidad respetable, pero
nunca al "blindado total". Quien te diga lo contrario está mintiéndote.

- **Live edge**: el chunk más reciente disponible en cualquier punto del mesh
- **Sliding window**: rango de chunks [oldest..newest] en buffer
- **Bitmap**: representación compacta de qué chunks tiene un peer (16 bits)
- **Super-seeder**: peer con upload alto que sirve a 10-20 viewers
- **Mid / Leaf**: niveles intermedios y finales del árbol P2P
- **Churn**: rate de viewers entrando/saliendo (típico 5-10% por minuto en live)
- **HP / Hole-punch**: técnica para que dos peers detrás de NAT se conecten
- **HighID / LowID**: en eMule, HighID = puerto entrante alcanzable, LowID = no
- **ABR**: Adaptive Bitrate, múltiples calidades, cliente elige según red
- **SVC**: Scalable Video Coding, capas que se combinan para distintas calidades
- **Tree formation**: algoritmo que decide la topología del mesh
- **Multi-parent**: viewer con N>1 sources concurrentes

---

## 13. Seguridad adicional + Incentivos para super-seeders

Sección 12 cubre las amenazas obvias. Esta cubre:
- **13.1-13.5**: capas de seguridad NO cubiertas en sección 12 (code hardening,
  network encryption, privacy, trust verification)
- **13.6-13.9**: sistema de incentivos para super-seeders (con análisis de
  cuándo crypto SÍ y cuándo NO)

### 13.1 Code-level hardening (lo que falta a nivel de código C++)

eMule 0.70b es código C++ de 20+ años. Aunque hemos añadido fixes, el
codebase no fue diseñado con security-first mindset. Lo que falta:

| # | Problema | Fix concreto | Esfuerzo |
|---|---|---|---|
| **C1** | Packet parsing sin bounds checking | Auditar todos los `OP_LIVE_*` handlers en LiveStreamManager.cpp / WebServer.cpp. Cada `*(uint32*)ptr` necesita validar `ptr + 4 <= end` | 1-2 semanas |
| **C2** | Integer overflow (vimos uno en uint32 underflow) | `safe_int<T>` template wrapper para arithmetic ops, especially seq numbers, sizes | 1 semana |
| **C3** | Uso de funciones C peligrosas | grep `strcpy\|sprintf\|gets\|strcat` y reemplazar por `_s` versions o std::string | 3 días |
| **C4** | Memory leaks en error paths | Migrar `new`/`delete` a `unique_ptr`/`shared_ptr` en código nuevo | continuo |
| **C5** | Race conditions en mesh | Lock auditing — cada acceso a `m_meshPeers`, `m_chunkBuffer` revisado | 1-2 semanas |
| **C6** | No fuzz testing | AFL++ contra protocol parsers (LivePackets.cpp). 1-2 días setup, descubre bugs sin parar | 1 sem |
| **C7** | No sanitizers en CI | ASAN + UBSAN + TSAN builds en CI. Falla cualquier PR con UB. | 2 días |
| **C8** | Inputs de usuario sin sanitizar | Stream titles/categories en HTML/JSON sin escape correcto. XSS vector. | 2 días |
| **C9** | Stack-allocated buffers fijos | `char buf[256]` con `sprintf` — convertir a heap o validar entrada | 1 sem |
| **C10** | Crash dumps con info sensible | Configurar Mdump (eMule lo tiene) para que no incluya passwords/keys | 1 día |

**Recomendación**: C6 (fuzz testing) + C7 (sanitizers en CI) tienen el ROI más
alto — descubren bugs reales automáticamente. Hacer YA, antes que cualquier
otra cosa de hardening.

### 13.2 Network-level: encryption beyond transport TLS

Hoy el plan asume que SRT/QUIC encriptan en transporte (DTLS-SRTP-style).
Pero eso solo protege **point-to-point** (peer-a-peer). Un super-seeder
malicioso puede:
- Ver el contenido del stream completo
- Registrar metadata: quién pide qué chunks
- Modificar chunks (mitigado por PPSPP signed hashes — buen catch ya en plan)

**Lo que falta: end-to-end encryption (E2EE) del stream**:

```
Broadcaster genera AES key K para el stream
K se distribuye a viewers FUERA del mesh (link compartido)
   - Anonymous link: stream_key|K_encrypted_with_password
   - Direct link: stream_key|K en claro (asumiendo viewer es trusted)
Cada chunk va cifrado con K antes de entrar al mesh
Super-seeders relayean BLOBS opacos — no pueden ver el contenido
Solo viewers con K pueden descifrar
```

**Implicaciones**:
- ✅ Super-seeders no ven el contenido (gran win privacidad)
- ✅ Resistente a passive surveillance del ISP/state actor
- ⚠️ Distribución de K es el problema clásico de KEY MANAGEMENT
- ⚠️ Viewer banneado puede compartir K con otros (no rotación = broken)
- ⚠️ Coste CPU encryption en broadcaster, decryption en cada viewer (~2-5% CPU)

**Diseño sugerido v3**:
- AES-256-GCM por chunk con nonce derivado de seq_num
- Key rotation cada 60s con HKDF (forward secrecy)
- Distribuir keys via signaling channel cifrado (TLS al tracker)
- Optional: viewers con membership badge tienen acceso continuo

### 13.3 Privacy enhancements

Más allá de E2EE de contenido, hay metadata que sigue expuesta:

| Metadata | Quién lo ve | Mitigación |
|---|---|---|
| IP del viewer | Broadcaster, super-seeders, sus parents | Inevitable en P2P sin onion routing |
| IP del broadcaster | Super-seeders, viewers con direct link | Anonymous link mitiga (broadcaster IP no en link) |
| ¿Qué stream ves? | Tu super-seeder, atacante con muchos peers correlacionando | Onion routing (latencia 10x), out of scope para v3 |
| ¿A qué hora? | Tu ISP (siempre), atacante con peers | Mismo, inevitable sin mixnets |
| Bitrate / quality elegido | Tus parents | Inferible aunque uses E2EE |
| Bytes consumidos | ISP, parents | Padding cover traffic resolvería pero coste 2-3x bandwidth |

**Lo que SÍ es realista incluir**:

1. **Anonymous link por defecto en MFC** (ya planeado v2)
2. **Stream key rotation periódica**: broadcaster puede rotar K cada N
   minutos para invalidar acceso de viewers expulsados
3. **Optional Tor bridge**: viewer puede conectarse a un super-seeder
   vía Tor SOCKS proxy. Latencia 5-10s aceptable para "stream lecture".
4. **Padding mode opcional**: viewer puede pedir "send junk packets to
   match my normal pattern" — protege contra traffic analysis del ISP.
   Coste: 1.5-2x bandwidth. Solo para usuarios paranoid.

### 13.4 Trust verification (releases, supply chain)

| # | Mitigación | Concreto | Esfuerzo |
|---|---|---|---|
| **T1** | Signed releases | GPG-sign emule.exe + ZIP. Public key publicado en proyecto repo | 1 día setup |
| **T2** | Reproducible builds | Toolchain pinned, build env containerizado (Docker) | 2-3 semanas |
| **T3** | SBOM (Software Bill of Materials) | Generar SPDX/CycloneDX de TODA dep + version + hash | 1 semana |
| **T4** | Pinned dep versions | `package-lock.json` para Node, vcpkg manifest para C++ | 1 día |
| **T5** | Vulnerability scanning automatizado | Snyk / Dependabot / OSV-Scanner en CI | 2 días |
| **T6** | Vulnerability disclosure policy | SECURITY.md en repo, email security@..., 90-day disclosure | 1 día |
| **T7** | Release notes con CVE history | CHANGELOG.md público listando vuln history y fixes | continuo |
| **T8** | Update mechanism in-app | Auto-check de versión, alerta de "tu versión tiene CVE-XXXX" | 1 semana |

**Recomendación**: T1 + T4 + T5 son MUY baratos y dan defensa enorme contra
supply chain attacks. T2 (reproducible builds) es el gold standard pero
trabajoso — postponer.

### 13.5 Authentication / authorization layer

Hoy el sistema es "stream key implícita = autorización". Eso funciona
pero limita features:

**Lo que falta**:
1. **Broadcaster admin token**: para revocar stream key, kickear viewers,
   ver lista de viewers conectados. Compartido vía OS keyring del broadcaster.
2. **Per-viewer session tokens**: identifican una sesión de viewer.
   Permiten: bannear viewer específico, métricas por viewer, concurrent limit
3. **Capability tokens**: tokens con scopes (`read-only`, `read+contribute`, `read+admin`)
4. **Tracker permissions**: super-seeders verificados con acceso preferencial

**Implementación sugerida**: JWT con HS256 (HMAC), key del broadcaster.
Stateless, no requiere DB. Validación en cada packet. Coste CPU ~0.1ms.

### 13.6 Sistema de incentivos para super-seeders

**El problema**: super-seeders gastan upload (BW + electricidad) para que
otros vean. Sin incentivo, solo altruistas dedican BW. Network effect cae.

**Modelos posibles** (de menor a mayor controversia):

| # | Modelo | Cómo funciona | Pros | Contras |
|---|---|---|---|---|
| **0** | Altruismo puro | Nada | Cero complejidad | No escala más allá de entusiastas |
| **1** | Reputación / badges | Score público "you have shared X TB" | Trivial, gamificación | Solo motivación intrínseca |
| **2** | Quality reward | Super-seeders ven en mejor calidad / menos latencia | Técnico, no requiere identity | Solo útil si ABR activo |
| **3** | Tree position reward | Super-seeders altos en árbol = lowest latency | Alineado con arquitectura | Difícil "ganar" si entras tarde |
| **4** | Service reward | Unlock features: más streams, longer broadcasts, custom branding | Sin dinero, alinea con producto | Requiere sistema de tiers complejo |
| **5** | Direct tipping | Broadcaster envía propina manual | Real value, no obligatorio | Requiere wallet, infra de pagos |
| **6** | Crypto micro-payments | Per-byte/per-chunk payment automático en token X | Mercado real, escala | Regulación + complejidad enorme |
| **7** | Token economy completa | Ecosistema con stake, gobernanza | Network effect económico | Securities laws, brittle |

**Comparación honesta con sistemas existentes**:
- **BitTorrent**: altruism + tit-for-tat funciona porque es symmetric. Para
  LIVE (asymmetric) tit-for-tat NO aplica directamente.
- **Theta Network**: tokens THETA + TFUEL. Funciona económicamente pero
  técnicamente es un CDN de pago disfrazado de P2P.
- **Filecoin / Storj**: pagan por almacenamiento, no streaming. Más simple.
- **Lightning Network sat-streaming**: micro-pagos en BTC por byte.
  Técnicamente posible, regulatoriamente complejo.

### 13.7 Recomendación concreta de incentivos para nuestro caso

**Diseño en 3 niveles**, opt-in progresivo:

#### Nivel 1 — Reputation + Quality (v2-v3, BAJO RIESGO)

Sin dinero, sin crypto, sin identidad fuerte. Solo técnico:

```
Cada peer tiene un trust_score local (0-1000):
  + uptime_minutes (max 500 puntos)
  + bytes_served / 10MB (max 300 puntos)
  + endorsements_from_other_peers (max 200 puntos)
  - timeout_count × 10 (penalización)

trust_score determina:
  - tree_position: alta = lower latency, closer to broadcaster
  - quality_variant: alta = priority access to top ABR
  - concurrent_streams_allowed: alta = puede ver N streams a la vez
  - visible_badge: opcional UI muestra "Super-Supporter" / "Mega-Seeder"
```

**Implementación**:
- Cada cliente trackea su propio score (cumulative across sessions)
- Scores SE COMPARTEN con peers vía HEARTBEAT extendido
- Validación cruzada: si peer X dice "me serviste 100MB", peer Y verifica
  vs sus propios contadores → si mismatch, score X queda bajo sospecha
- Persistencia: score guardado en preferences.ini, cifrado con MAC
  vinculado a hardware fingerprint (anti-trivial-tampering)

**Cost**: 1-2 semanas de engineering. Sin regulación, sin terceros.

#### Nivel 2 — Service Tiers (v3, MEDIO RIESGO)

Desbloquear features según tier:

| Tier | Trust score | Features unlock |
|---|---|---|
| **Leech** | <100 | Solo SD (lowest ABR), 1 stream concurrent |
| **Casual** | 100-300 | HD opcional, 2 streams |
| **Contributor** | 300-700 | FullHD, 3 streams, broadcast hasta 6h |
| **Super-Seeder** | 700-1000 | 4K, ilimitado, broadcast unlimited, badge UI |
| **Mega-Seeder** | 1000+ (sostenido 1 mes) | Tree apex priority, custom URL, governance vote |

**Implementación**:
- Lógica de unlock en cliente (broadcaster + viewer)
- Validación cross-peer del trust_score (anti-cheat)
- Badges en UI (visible para todos)
- Possibly: super-seeders pueden ELEGIR qué streams priorizar

**Cost**: 2-3 semanas + design del tier system.

#### Nivel 3 — Crypto Tipping (v4+, ALTO RIESGO)

Solo si hay demanda real y aceptas complejidad regulatoria:

**Opción A — Lightning Network tipping voluntario** (RECOMENDADA si crypto):
- Broadcaster genera invoice Lightning para tipping
- Viewer scanea QR del invoice → paga sats
- Sats van directo al broadcaster
- Broadcaster opcionalmente reparte a super-seeders top
- **Sin token propio, sin contratos inteligentes, sin securities risk**

**Opción B — Token economy completa (NO RECOMENDADO)**:
- Token propio con consenso
- Pago automático por byte servido
- Stake para anti-Sybil
- **Securities laws nightmare, complexity huge, brittle**

**Mi recomendación**: NO implementar crypto en v3-v4 a menos que la
comunidad lo demande explícitamente. Hay alta probabilidad de que el
nivel 1+2 sean SUFICIENTES si hay community engagement.

### 13.8 ¿Cuándo crypto SÍ tiene sentido?

Solo si:
1. La red llega a >10k viewers con sostenida demanda
2. Hay broadcasters que generan ingresos (ads, sponsorships, etc.)
3. Hay desarrollador legal disponible para due diligence
4. Comunidad lo pide explícitamente (no imponerlo)

Si es "sí" a los 4: Lightning tipping es el camino. NO inventar token propio.

### 13.9 Roadmap de seguridad + incentivos consolidado

| Fase | Trabajo | Tiempo | Win |
|---|---|---|---|
| **S-A** Code hardening básico | C1 (bounds), C6 (fuzz), C7 (sanitizers) | 2-3 sem | Defensa contra bugs |
| **S-B** Trust verification | T1 (signed releases), T4 (pinned deps), T5 (vuln scanning) | 1 sem | Supply chain defense |
| **S-C** Auth tokens | JWT-based session tokens | 1 sem | Granular permissions |
| **I-1** Incentivos nivel 1 | Trust score + tree position | 1-2 sem | Network effect arranca |
| **S-D** E2EE de payload | AES-256-GCM + key rotation | 2-3 sem | Super-seeders no leakean contenido |
| **I-2** Incentivos nivel 2 | Service tiers + badges | 2-3 sem | UX engaging |
| **S-E** Privacy options | Optional Tor bridge, padding mode | 3-4 sem | Privacy-conscious users |
| **S-F** Reproducible builds | Containerized build env | 2-3 sem | Hardened distribution |
| **I-3** Crypto tipping (OPCIONAL) | Lightning Network invoice | 2 sem | Real economic incentive |

**Total trabajo s+i v3-v4**: ~3-4 meses adicionales sobre el roadmap base.

### 13.10 Resumen de recomendación

**Empezar por** (impacto/esfuerzo más alto):
1. **C6 (fuzz testing)** — descubre bugs automáticamente, sin esfuerzo continuo
2. **C7 (sanitizers en CI)** — falla PRs con UB
3. **T1 + T4 + T5 (signed releases + pinned deps + vuln scan)** — supply chain
4. **I-1 (trust score)** — incentiva super-seeders sin dinero

Esos 4 son **2-3 semanas total**, dan **80% del valor de seguridad y
incentivos** sin complejidad regulatoria.

**Para v3-v4**:
5. E2EE de payload (S-D) — privacy real
6. Service tiers (I-2) — engagement con super-seeders
7. JWT auth (S-C) — granular permissions

**NO HACER hasta tener community real**:
- Crypto tipping (I-3): solo si hay demanda
- Token propio: nunca, regulatoriamente tóxico

**El "premio" para super-seeders correctamente diseñado es**:
1. **Técnico**: más calidad, menor latencia, posición top en árbol
2. **Reconocimiento**: badge visible, status en comunidad
3. **Funcional**: unlock features (multi-stream, longer broadcast)
4. **Opcional crypto**: solo si hay demanda y soporte regulatorio

**No es necesario crypto** para que el sistema funcione. PPLive y
CoolStreaming llegaron a 30-100k viewers sin un solo token. La clave es
que el "premio" sea PERCIBIDO como valioso por el super-seeder, no
necesariamente que sea dinero.

---

## 14. Anonimidad del broadcaster: ¿es posible?

**Sí, parcialmente, con tradeoffs claros.** La anonimidad perfecta de un
broadcaster en P2P live es uno de los problemas más duros del campo. Esta
sección lista las 5 técnicas viables, sus compromisos, y qué amenaza concreta
defeats cada una.

### 14.1 Por qué es DURO

Principio fundamental: **en cualquier sistema P2P, alguien debe recibir
los datos primero del broadcaster**. Ese "primer receptor" conoce la IP
del broadcaster por definición.

```
Broadcaster envía bytes → primer hop ve IP origen
                       → segundo hop ve IP del primer hop
                       → ... cadena propaga
```

Para que el broadcaster sea anónimo, hay que **romper esta cadena de
"primer receptor"**: o el primer receptor no sabe que es el primer
receptor, o tu IP queda enmascarada antes de llegar al primer receptor.

### 14.2 Modelo de amenaza (qué se quiere proteger)

Antes de elegir técnica, hay que definir contra QUIÉN se protege:

| Adversario | Capacidad | Qué amenaza al broadcaster |
|---|---|---|
| **Viewer casual** | Tiene el link, recibe el stream | ¿Puede saber tu IP solo viendo? |
| **Viewer activo** | Modifica su cliente, snifa packets | ¿Puede deducir IP correlacionando? |
| **ISP del broadcaster** | Ve TODO el tráfico saliente | ¿Sabe que estás emitiendo y a quién? |
| **ISP del viewer** | Ve tráfico entrante del viewer | ¿Sabe el viewer está viendo TU stream? |
| **Atacante con N peers falsos** | Puede unirse al mesh, observar | ¿Puede correlacionar para identificarte? |
| **Estado / orden judicial** | Puede subpoena a cualquier relay/ISP | ¿Pueden los relays revelar tu identidad? |
| **Atacante con visibilidad global** | Ve internet entero (NSA-level) | ¿Análisis de tráfico te identifica? |

Cada técnica defeat un subconjunto distinto. **Honesto: ninguna técnica
defeats a un atacante con visibilidad global de internet (NSA-level)**.

### 14.3 Técnicas disponibles (5 enfoques)

#### A. Anonymous link (LO QUE YA TENEMOS)

```
Link: ed2k://|live|HASH||TITLE|/   (sin IP)
```

**Cómo funciona**: el viewer descubre la IP del broadcaster vía Kad search,
NO desde el link. El link no expone nada.

**Defeats**: viewer casual mirando el link.

**NO defeats**: cualquier viewer que se conecte. Una vez subscrito vía Kad,
el viewer conoce la IP del broadcaster (es a quien se conectó).

**Coste**: cero, ya implementado.

**Adecuado para**: privacidad básica + "no quiero que mi IP esté en el link
que circula por WhatsApp".

#### B. Relay-first architecture (LA RECOMENDADA, similar a Tor guard nodes)

```
Broadcaster → 3-5 trusted "entry relays" (super-seeders auto-elegidos)
            → mesh
                
Mesh peers ven solo entry relay IPs. Broadcaster IP nunca aparece en mesh.
```

**Cómo funciona**:
- Al arrancar, broadcaster busca super-seeders top-tier vía Kad
- Establece conexiones cifradas con 3-5 de ellos (entry relays)
- Solo emite a esos 3-5 relays
- Esos relays publican a Kad como "fuente del stream"
- Los viewers descubren a los relays, no al broadcaster
- Los relays NO publican que son relays; aparecen como source

**Defeats**:
- Viewer casual: ✅ no ve IP broadcaster
- Viewer activo: ✅ solo ve IP de su relay
- Atacante N peers falsos: ✅ todos los peers ven solo relays
- ISP del viewer: ✅ tráfico va a relay, no a broadcaster

**NO defeats**:
- ISP del broadcaster: ❌ ve que envías a 3-5 IPs, sabe que emites
- Subpoena a un relay: ❌ el relay sabe tu IP, puede revelarla
- Atacante que compromete los 3-5 relays: ❌ puede conspirar

**Coste**: ~2-3 semanas engineering. Latencia +50-100ms (1 hop extra).

**Implementación clave**:
- Selection de relays: top trust_score + diversity (diferentes AS/países)
- Rotation: relays cambian cada 30 min para evitar permanent linking
- Encrypted tunnels: TLS o Noise framework entre broadcaster y relays
- Cover: relays sirven OTROS streams también, no solo el tuyo →
  observador externo no puede deducir cuál stream es tuyo

**Adecuado para**: el caso "no quiero que viewers/ISP de viewers/atacantes en
mesh sepan quién soy". 90% de casos prácticos.

#### C. Onion routing del broadcaster (LO ESTILO TOR, mayor anonimidad)

```
Broadcaster envuelve stream en 3 capas de encryption:
  Layer 1: AES con K_relay1
  Layer 2: AES con K_relay2  
  Layer 3: AES con K_relay3

Envia al Relay1 → quita capa 1, ve "envia a Relay2"
Relay1 → Relay2 → quita capa 2, ve "envia a Relay3"
Relay2 → Relay3 → quita capa 3, ve "publica al mesh"
Relay3 → publica como source
```

**Cómo funciona**: igual que Tor pero para datos broadcast en vez de unicast.
Cada relay solo conoce el anterior + el siguiente. Solo el LAST relay (Relay3)
sabe que el contenido va al mesh, pero no sabe quién es el broadcaster
original. Solo el FIRST relay (Relay1) conoce el broadcaster pero no sabe
si está enviando algo original o re-routeando.

**Defeats**:
- Todo lo de Relay-first ✅
- Subpoena a UN relay: ✅ solo conoce parte de la cadena
- Atacante que compromete 1-2 relays: ✅ no puede enlazar
- Atacante que compromete los 3: ❌ entonces sí
- ISP del broadcaster: ⚠️ ve que envías al primer relay (puede ser sospechoso pero no concluyente)

**Coste**: ~6-8 semanas engineering. Latencia +200-400ms (3 hops × encryption).
Bandwidth +0% (no overhead, las capas se quitan).

**Implementación**:
- Reuso de criptografía de libdatachannel (DTLS)
- Path selection: 3 relays de diferentes AS/países (anti-correlación)
- Path rotation: cambiar circuito cada 10-15 min (Tor lo hace cada 10)
- Padding: enviar paquetes vacíos cuando no hay datos para evitar análisis

**Adecuado para**: broadcaster paranoid que quiere anonymity tipo Tor. Coste:
3-5 segundos extra de latencia (todavía aceptable para "live").

#### D. Friend-to-friend (F2F, estilo RetroShare/Freenet)

```
Broadcaster solo conecta a peers PRE-AUTORIZADOS (lista de friends)
Esos friends propagan al mesh público
Mesh peers ven solo friend IPs
```

**Cómo funciona**: el broadcaster mantiene una lista de "trusted friends"
(añadidos por intercambio manual de PGP keys o similar). Solo emite a
esos friends. Los friends actúan como entry relays voluntarios.

**Defeats**:
- Todo lo de Relay-first ✅
- Atacante con peers falsos: ✅ no pueden ser tus friends sin tu invitación
- Sybil attack: ✅ identidad fuerte requerida

**NO defeats**:
- Friend traidor: ❌ confías en N personas
- Subpoena a un friend: ❌

**Coste**: ~4-5 semanas (sistema de identidad/keys). Latencia +50ms.

**Adecuado para**: broadcaster en círculo cerrado de confianza. NO escala
a streams públicos masivos.

#### E. Tor + Hidden Service (DISPONIBLE HOY sin nuestro código)

```
Broadcaster corre eMule sobre Tor SOCKS proxy
Configura .onion address (Hidden Service)
Viewers usan Tor browser para conectar a la .onion
```

**Cómo funciona**: usar Tor tal cual existe. eMule acepta SOCKS proxy. Tor
maneja todo el routing.

**Defeats**:
- Casi todo, hasta NSA-level análisis (con caveats)

**NO defeats**:
- Análisis de tiempos a escala global
- Tor exit attacks (no aplica aquí, es .onion)

**Coste**: 0 código en nuestra parte. Setup usuario complejo.

**Latencia**: **5-15 segundos** (Tor circuito típico). Bandwidth limitado a
~few Mbps. **Mata "live"** para casi todo uso.

**Adecuado para**: broadcaster con paranoia máxima dispuesto a sacrificar
latencia y calidad. Caso edge.

### 14.4 Comparativa resumen

| Técnica | Coste eng | Latencia extra | Defeats viewer/ISP | Defeats peers falsos | Defeats subpoena | Defeats global adversary |
|---|---|---|---|---|---|---|
| **A. Anon link** | 0 | 0 | ⚠️ solo link | ❌ | ❌ | ❌ |
| **B. Relay-first** | 2-3 sem | +50-100ms | ✅ | ✅ | ⚠️ relays saben | ❌ |
| **C. Onion** | 6-8 sem | +200-400ms | ✅ | ✅ | ✅ (1-2 hops) | ⚠️ |
| **D. F2F** | 4-5 sem | +50ms | ✅ | ✅ | ⚠️ friends | ❌ |
| **E. Tor** | 0 código | +5-15s | ✅ | ✅ | ✅ | ⚠️ |

### 14.5 Recomendación concreta para nuestro caso

**v3 (PRÁCTICO): Relay-first architecture (técnica B)** 

Razones:
- Cubre 90% de casos prácticos (viewer/ISP/peers maliciosos)
- Coste razonable (2-3 semanas)
- Latencia aceptable (+50-100ms, total stream <2s)
- **Compatible con la arquitectura ya planeada**: los super-seeders del
  plan v3 SON los entry relays, solo cambia que no exponen al broadcaster
- Sin complejidad regulatoria (no es Tor, no es crypto)

**v4 (PARANOID): Onion routing opcional (técnica C)**

Para broadcasters que quieren anonymity tipo Tor sin la latencia de Tor:
- Coste: 6-8 semanas
- Latencia: +200-400ms (todavía bajo 2.5s total)
- Defeats subpoena a 1-2 relays
- Toggle "Maximum anonymity" en UI

**NO RECOMENDADO**:
- F2F (D): muy útil para casos cerrados pero confunde con sistema general
- Tor nativo (E): mata latencia, perfecto para usuarios extremos pero no
  como default

### 14.6 Implementación detallada de Relay-first (técnica B)

**Cambios al protocolo**:

```
1. Broadcaster al arrancar:
   - Busca top-tier super-seeders vía Kad (trust_score > 700)
   - Filtra por: diferentes AS, diferentes países si posible
   - Selecciona 3-5 candidates

2. Establecer Entry Relay Tunnels (ERT):
   - Broadcaster → relay TLS handshake (mutual auth opcional)
   - Negocia stream key K (compartida con futuros viewers)
   - Establece tunnel cifrado bidireccional

3. Stream emission:
   - Broadcaster encripta cada chunk con K
   - Envia a los 3-5 relays vía sus tunnels
   - Relays NO descifran; reenvían como blobs opacos al mesh
   - Relays publican A KAD que ellos son "source" del stream
     (mienten estructuralmente, son relays no source)

4. Viewer connection:
   - Viewer busca stream → encuentra relays como source
   - Conecta a relay → recibe blobs cifrados
   - Descifra con K (que recibe del link)
   - Reproduce normal

5. Relay rotation:
   - Cada 30 min, broadcaster reasigna 1 de los 5 relays
   - Mantiene continuidad (no caer todos a la vez)
   - Reduces ventana de "permanent linking"

6. Cover traffic:
   - Cada relay sirve OTROS streams también (no solo el del broadcaster X)
   - Observador externo ve relay sirviendo "algún stream", no puede
     decir cuál
```

**Cambios al broadcaster** (LiveStreamManager.cpp):
- Nuevo método `EstablishEntryRelays()` con selection lógica
- Cifrar chunks con AES-256-GCM antes de enviar
- Mantener pool de 3-5 connections siempre activas
- Health check + rotation cada 30 min

**Cambios al super-seeder**:
- Aceptar rol "entry relay" cuando un broadcaster lo solicita
- Capacidad para reenviar blobs sin descifrar (no necesita K)
- Publicar a Kad bajo su propia IP (no del broadcaster)

**Cambios al viewer**:
- Recibir K del link (incluido en query string de ed2k:// o vía signaling)
- Descifrar chunks recibidos con K
- Sin cambios al flujo de mesh/discovery

**Métricas para validar**:
- Tiempo a primer chunk con relay vs sin relay (esperado +100-200ms)
- % broadcasters que consigan 3-5 relays (esperado >90% si super-seeders
  abundantes)
- Bandwidth overhead de tunnels TLS (~3-5%)

### 14.7 Lo que sigue sin solución (honesto)

Incluso con técnica B + C combinadas, sigue habiendo cosas no resolubles:

1. **ISP del broadcaster**: ve que envías ~3 Mbps continuos a 3-5 IPs.
   Sabe que estás haciendo SOMETHING que parece streaming. **No puede
   identificar el contenido** (cifrado), pero sí el comportamiento.
   
   Mitigación: usa una VPN antes de eMule. La VPN ve el tráfico cifrado,
   tu ISP solo ve un túnel a la VPN. Defeats al ISP, transfiere
   confianza a la VPN.

2. **Análisis de tiempos a escala**: si un atacante observa internet entero
   y ve tráfico saliendo de tu IP justo cuando entran chunks al primer
   relay, puede correlacionar. **Defeated solo por mixnets** (latencia 100×,
   inviable para live).

3. **Subpoena coordinada a TODOS los relays**: si autoridad puede subpoena
   los 3-5 relays simultáneamente, pueden reconstruir tu identidad. Onion
   routing (técnica C) hace esto MÁS DIFÍCIL pero no imposible.

4. **Compromiso de hardware/OS**: si tu PC está infectado con malware,
   nada de esto te protege. La anonymity está limitada por tu seguridad
   local.

5. **Legal**: en algunas jurisdicciones, "operar un servicio de
   broadcasting anónimo" puede ser ilegal independientemente del contenido.
   No podemos protegerte de leyes locales.

### 14.8 Threat model coverage final

Si implementamos B + C + las medidas auxiliares:

| Adversario | Cobertura |
|---|---|
| Viewer casual | ✅ 100% protegido |
| Viewer activo / packet sniffer | ✅ 100% (solo ve relay IPs) |
| ISP del viewer | ✅ 100% (tráfico va a relay, no a ti) |
| ISP del broadcaster | ⚠️ ve actividad, no contenido. Mitigado con VPN |
| Atacante N peers falsos en mesh | ✅ 100% (mesh nunca ve broadcaster IP) |
| Subpoena 1 relay | ✅ con onion (B no, C sí) |
| Subpoena varios relays | ⚠️ depende cuántos comprometidos |
| Estado con análisis de tiempos global | ❌ irresoluble sin mixnets |
| Hardware comprometido (malware) | ❌ fuera de scope |

### 14.9 Recomendación final sobre anonimidad

**Para v3**: implementar técnica B (Relay-first). Coste 2-3 semanas, cubre
el 90% de casos prácticos. Hacerlo **default** para todos los broadcasters.

**Para v4**: añadir técnica C (Onion routing) como **toggle opcional**
"Maximum anonymity" en UI. Para broadcasters que aceptan la latencia
extra a cambio de defeating subpoenas individuales.

**Mensaje al usuario en UI**:
```
[ ] Anonymous broadcaster mode (recomendado)
    Tu IP no se expone a viewers. Latencia +100ms.

[ ] Maximum anonymity (avanzado)
    Routing tipo Tor: 3 hops. Latencia +400ms.
    Resistente a subpoena de relays individuales.
    
[ ] Direct mode (no anonymity)
    Tu IP visible al mesh. Latencia mínima.
    Solo recomendado para tests / amigos.
```

**Realidad honesta**: el broadcaster anónimo es **alcanzable a nivel
"protección práctica"**. La anonimidad **absoluta** (NSA-proof) no es
posible en P2P live sin sacrificar la "vivacidad". Nuestra propuesta es
el sweet spot: protección real contra todos los adversarios prácticos
(viewers, ISPs, peers maliciosos), con reconocimiento honesto de los
límites contra adversarios extremos.

---

## 15. Mejorar la red Kad / eD2K desde nuestra posición

**Sí, mucho.** Tenemos el código fuente, podemos modificar Kad, somos
parte de la red. Hay 6 categorías de mejoras desde "fácil y aprovechable
hoy" hasta "contribución a largo plazo a la salud de la red eD2K global".

### 15.1 ¿Por qué importa?

Kad es una red distribuida que ha funcionado desde 2004. Tiene problemas:
- Mainline eMule prácticamente sin mantenimiento desde ~2010
- Código C++ de 2002, sin modernización
- IPv6 no soportado (perdemos a media Europa)
- Pollution attacks históricos (spam de keys falsas)
- Bootstrap lento (5-15 min en cold-start)
- Nodos de calidad declinante (peers domésticos 2002 ≠ 2026)

Como fork, podemos:
1. **Mejorar para nuestros usuarios** (cambios en nuestro fork)
2. **Mejorar para la red entera** si otros clientes adoptan nuestras mejoras
3. **Contribuir código upstream** (si la comunidad eMule lo acepta)
4. **Ser "buen ciudadano"**: nuestros peers son honestos, fiables, ayudan a otros

### 15.2 Mejoras específicas a Kad (DHT)

#### 15.2.1 Bigger k-buckets

Hoy: Kademlia clásico, k=10 contactos por bucket.

**Mejora**: aumentar a k=20 o k=40. Más contactos = más resilience
ante churn, más opciones para routing.

**Cambio en código**: `srchybrid/kademlia/kademlia/Defines.h`
```cpp
// Hoy:
#define K 10

// Propuesto:
#define K 20  // o 40 si memoria sobra
```

**Coste**: memoria (cada contacto ~50 bytes × N buckets × K contactos =
~50 KB → ~100-200 KB). Negligible.

**Beneficio**: lookups más rápidos, churn mejor absorbido.

**Esfuerzo**: 1 hora (cambio constante + tests).

#### 15.2.2 Parallel lookup (alpha)

Kademlia paper sugiere alpha=3 (3 lookups paralelos). eMule usa alpha=3.
Subir a alpha=10 acelera lookups dramáticamente para nuestro caso live
(donde latencia importa).

**Cambio**: `srchybrid/kademlia/kademlia/Search.cpp` constant ALPHA.

**Coste**: más mensajes UDP (10x los actuales en lookup phase). En
moderno bandwidth = nada. En tracker bandwidth = significa los nodos
buscados reciben más queries simultáneas (carga ~3x).

**Beneficio**: lookup latency ~5x más rápido (de 5s a 1s típico).

**Esfuerzo**: 1 día (cambio + benchmarking).

#### 15.2.3 Aggressive bucket refresh

Hoy: eMule refresca buckets cada hora. Si un nodo cae, se detecta
lento.

**Mejora**: refresh cada 10 min para buckets activos, marca dead nodes
más rápido.

**Cambio**: `srchybrid/kademlia/routing/RoutingZone.cpp`.

**Coste**: 6x más bandwidth de refresh (~5 KB/min en vez de 5 KB/h).

**Beneficio**: routing table siempre fresca, menos timeouts.

**Esfuerzo**: 1-2 días.

#### 15.2.4 IPv6 awareness en Kad

Hoy: Kad solo IPv4. Si peer A solo tiene IPv6, no participa.

**Mejora**: extender contact info para incluir AAAA, dual-stack lookup.

**Cambio mayor**: `srchybrid/kademlia/io/IOBuffer.cpp`, formato del
contact serialization, todo el routing.

**Coste**: protocolo nuevo, no compatible con clientes IPv4-only viejos
(necesita versioning).

**Beneficio**: 50% de Europa entra a la red sin NAT. Game changer.

**Esfuerzo**: 3-4 semanas (es un cambio profundo).

#### 15.2.5 Smart bootstrap nodes.dat curado

Hoy: nodes.dat shipped con eMule es de hace años, mucha basura.

**Mejora**: ship nodes.dat **fresco y curado**:
- Nodos verificados online >24h
- Diversos geográficamente
- Diversas versiones de cliente
- Re-generar periódicamente desde nuestra red

**Cambio**: integrar en nuestro CI un job que cada noche:
1. Lanza emule headless, conecta a Kad 1h
2. Vuelva a guardar nodes.dat
3. Lo incluye en próximo release

**Coste**: VPS pequeño ~$5/mo o GH Actions free.

**Beneficio**: bootstrap de 5-15 min reducido a 5-30 segundos.
**Enorme** UX mejora para nuevos usuarios.

**Esfuerzo**: 1 semana setup CI + script.

### 15.3 Mejoras a eD2K (protocolo TCP)

#### 15.3.1 Modernizar handshake

eMule handshake usa OP_HELLO con campos fijos de 2002. Añadir:
- Negociación de extensiones (capabilities bitmask)
- TLS opcional para conexiones (hoy todo plaintext)
- Compresión opcional del control plane (gzip)

**Coste**: backward-compat con clientes viejos (tienen que asumir defaults).

**Beneficio**: privacidad mayor, futuras extensiones fáciles.

**Esfuerzo**: 1-2 semanas.

#### 15.3.2 Multiplexing de conexiones

Hoy: cada peer = 1 conexión TCP. Si tienes 50 viewers + 50 sources, son
100 conexiones. Algunos OS limitan, kernel overhead alto.

**Mejora**: multiplexar varios "stream channels" sobre 1 conexión TCP
(o mejor: QUIC/SRT que ya soportan multiplex nativo).

**Beneficio**: menos socket overhead, mejor scaling.

**Esfuerzo**: 2-3 semanas (cambia mucho ListenSocket / ClientUDPSocket).

#### 15.3.3 Better source exchange

Hoy: peer A tells peer B "estos son otros peers que conozco para este
file/stream". Útil pero limitado (5-10 contactos).

**Mejora**: source exchange más inteligente — share TOP peers (mejor
RTT, mejor ratio histórico, más uptime).

**Beneficio**: convergencia más rápida del swarm.

**Esfuerzo**: 1 semana.

### 15.4 Contribución de código a mainline eMule

eMule mainline en SourceForge está casi muerto, pero el código es libre
(GPL) y nuestras mejoras pueden:

**Lo que podríamos contribuir back**:
1. Bug fixes (especialmente memory leaks que encontremos con sanitizers)
2. Modernización C++ (smart pointers, RAII)
3. Compatibilidad con Windows 11/12 (eMule tiene warnings)
4. IPv6 support (sería el cambio más grande y valioso)
5. CI/CD setup (eMule no tiene tests automáticos)
6. Performance optimizations medidas con profiling

**Lo que NO contribuiríamos** (queda en nuestro fork):
- Live streaming (es nuestro feature diferenciador)
- WebRTC bridge
- Cualquier cosa que la comunidad eMule considere "fuera de scope"

**Realismo**: la comunidad eMule es pequeña y conservadora. Aceptarán
bug fixes y modernización pero rechazarán features grandes. Aún así,
contribuir es **buen ciudadano** y **da visibilidad**.

**Esfuerzo**: 1-2 PRs/mes, sustainable.

### 15.5 Network health: ser buen ciudadano

Cosas que mejoran la red eD2K/Kad GLOBAL solo por nuestros peers existir:

#### 15.5.1 Always-on relay nodes (trusted volunteers)

Algunos super-seeders pueden ofrecerse como **relay para hole-punch
helper a OTROS clientes** (no solo nuestro fork).

**Cómo**: implementar uTP BEP 55 holepunch endpoint que cualquier
eMule cliente puede usar. Nuestros peers HighID actúan como rendezvous
para LowID-LowID de otros forks.

**Beneficio**: más conectividad en la red global.

**Esfuerzo**: 2-3 semanas (implementar BEP 55 si no está completo).

#### 15.5.2 Cache distributed de hashes populares

eD2K busca por hash MD4 del archivo. Hoy cada lookup va a Kad.

**Mejora**: nuestros peers cachean los TOP 1000 lookups más vistos en
los últimos días, sirven local hits inmediatos.

**Beneficio**: reducción dramática de carga en la DHT global.

**Esfuerzo**: 1-2 semanas.

#### 15.5.3 Anti-pollution

Kad históricamente tiene **pollution attacks**: spammers publican
millones de keys falsas para aplastar lookups legítimos.

**Mejora**:
- Nuestros peers REPORTAN sospechas a un agregador opt-in
- Bloqueamos peers conocidos como spammers (community blocklist)
- Validamos resultados (si una key tiene metadata absurda, descartar)

**Beneficio**: red Kad más limpia.

**Esfuerzo**: 2-4 semanas.

#### 15.5.4 NAT-T helpers

Cuando nuestros peers HighID detectan que un peer LowID no consigue
conectar a OTRO LowID, ofrecemos ayuda hole-punch:
- Recibir SYN del que inicia
- Reenviar packet "abre" al destino
- Desaparecer (peer-to-peer toma el relevo)

**Beneficio**: red global con menos peers atrapados en LowID.

**Esfuerzo**: 1-2 semanas (BEP 55 ya parcial en libutp).

### 15.6 Modernización oportunidades

#### 15.6.1 Crypto modernization

eMule usa MD4 (broken since ~2005), AES-128 con modos viejos, OpenSSL
versiones antiguas.

**Mejora**:
- BLAKE3 o SHA256 para nuevos identificadores (mantener MD4 para
  compat de archivos existentes)
- AES-256-GCM para todo nuevo cifrado (mejor que AES-128-CBC)
- OpenSSL 3.x

**Beneficio**: futuro-proof crypto.

**Esfuerzo**: 1-2 meses (cambio profundo).

#### 15.6.2 Modern UI / web frontend

eMule MFC UI es de 2003. Nuestro Node dashboard es modernización.

**Mejora**: web UI completa que reemplaza MFC (eventualmente headless
+ web only).

**Beneficio**: cross-platform (Linux/Mac/web), modern UX.

**Esfuerzo**: 3-6 meses.

#### 15.6.3 Mobile client

No existe eMule mobile. WebTorrent existe pero limitado.

**Mejora**: app móvil que actúa como leaf-only viewer (consumer).

**Beneficio**: 100× la audiencia (mobile users que ahora no participan).

**Esfuerzo**: 4-6 meses (nuevo proyecto entero, iOS + Android).

### 15.7 Lo que vamos a CONTRIBUIR vs lo que queda en NUESTRO fork

| Cambio | Contribuir mainline | Mantener en fork | Razón |
|---|---|---|---|
| Bug fixes (memory leaks) | ✅ | — | Bien recibidos por todos |
| IPv6 support en Kad | ✅ | — | Beneficia red global |
| Bigger k-buckets, alpha=10 | ✅ | — | Mejora red global |
| Smart bootstrap nodes.dat | ✅ | — | Bien para todos |
| BEP 55 holepunch endpoint | ✅ | — | Compatibilidad amplia |
| Modernización C++ | ✅ | — | Code quality |
| Live streaming | ❌ | ✅ | Feature diferenciador |
| WebRTC bridge | ❌ | ✅ | Específico nuestro |
| SRT transport | ❌ | ✅ | Cambio mayor |
| RLNC FEC | ❌ | ✅ | Específico live |
| Anonymity (relay-first, onion) | ❌ | ✅ | Específico live |
| Trust score / auto-tier | ❌ | ✅ | Específico nuestro |

### 15.8 Roadmap práctico de "mejoras a la red"

**Mes 1: low-hanging fruit (mejoras nuestro fork, baratas)**
1. Bigger k-buckets (1h)
2. Alpha=10 lookup parallelism (1 día)
3. Smart bootstrap nodes.dat (1 sem)
4. Aggressive bucket refresh (2 días)

**Mes 2-3: mejoras medianas**
5. NAT-T helper (BEP 55) (2 sem)
6. Multi-keyword publish para live ya hecho
7. Distributed cache hashes populares (2 sem)

**Mes 4-6: contribución upstream**
8. Memory leaks audit + fix (continuo)
9. PRs a eMule mainline (cada mes)
10. CI/CD setup compartido

**Mes 6-12: cambios grandes**
11. IPv6 support full (3-4 sem dedicadas)
12. Crypto modernization (2 meses)
13. Modern web UI (en paralelo con Node dashboard, 6 meses)

**Mes 12+: ambicioso**
14. Mobile app
15. Wallpaper Federation con otros forks (eMule++, etc.)

### 15.9 Métricas de éxito

Si implementamos 15.8 completo:

| Métrica | Hoy | Tras mejoras |
|---|---|---|
| Bootstrap time (cold) | 5-15 min | <30s |
| Kad lookup latency | 5-15s | <2s |
| % peers IPv6-reachable | 0% | ~50% (mercados con FTTH+IPv6) |
| % LowID convertidos a HighID | ~30% | ~60% (NAT-T helper) |
| Pollution rate detectada | desconocido | medido + mitigado |
| Code quality (memory leaks/CVE) | unknown | tracked + fixed |

### 15.10 Filosofía: "Don't fork to compete, fork to improve"

Nuestro objetivo NO es matar eMule mainline ni hacer "el mejor cliente
ed2k". Es **añadir live streaming sobre la base de eD2K/Kad** y, de
camino, **mejorar la red para todos**.

La distinción importa:
- Si vemos eMule mainline como competidor → no contribuimos código
- Si vemos eMule mainline como base → contribuimos lo que beneficia
  a todos, mantenemos privado lo que es nuestro feature

**Ganamos los dos lados**: nuestros usuarios disfrutan live + mejor red,
la comunidad eMule entera disfruta nuestras mejoras.

### 15.11 Riesgos

- **Comunidad eMule rechaza nuestros PRs**: mantenedores conservadores,
  pueden no aceptar IPv6 por riesgo. Mitigación: mantener fork separado,
  documentar bien.
- **Ataques a la red**: si nuestros nodos son top-tier, atraen DDoS.
  Mitigación: rate limit, IPFilter, super-seeders rotativos.
- **Fragmentación**: si introducimos cambios incompatibles, partimos la
  red en dos. Mitigación: TODOS los cambios backward-compatible
  via versioning.
- **Demanda de mantener compatibilidad legacy nos lentea**: cierto.
  Aceptable trade-off por preservar la red.

### 15.12 Resumen: sí, podemos mejorar Kad/eD2K mucho

Lo más impactante en orden:

1. **Smart bootstrap nodes.dat** (1 sem, fix bootstrap UX masivo)
2. **Alpha=10 + bigger k-buckets** (2 días, lookups 5x más rápidos)
3. **NAT-T helper BEP 55** (2 sem, libera ~30% LowID)
4. **IPv6 support** (3-4 sem, +50% Europa accesible)
5. **Distributed hash cache** (2 sem, reduce DHT load)
6. **Anti-pollution** (2-4 sem, red más limpia)
7. **Mainline contributions** (continuo, beneficia todos)

Total ~3-6 meses de trabajo dedicado SOLO a mejorar la red base.
**Beneficio**: red eD2K/Kad más rápida, más resistente, más moderna.
Ganan nuestros usuarios + la comunidad eMule entera.

---

## 16. Estado de implementación (sesión 2026-05-15)

**Bloque V2 (sprint planificados S01-S30) — IMPLEMENTADO + COMMITEADO**:

| Bloque | Sprints | Commit | Estado |
|---|---|---|---|
| A. Observabilidad | S01-S05 | `ac59bc4`, `9990177` | ✅ Per-peer counters, 60s window, RTT EWMA via PING/PONG, /api/live/metrics Prometheus, latency histogram p50/p95/p99 |
| B. Stress simulator | S06-S10 | `6fd7af8` | ✅ --headless / --viewer / --metrics-port / --selftest flags, orchestrator.js + dashboard.html + sweep.js |
| C. Auto-tier + ratio | S11-S15 | `2bb882e` | ✅ MeasureUploadCapacity, ComputeMyTier (5 niveles), MaxConcurrentUploads, ratio gradient throttle, bootstrap grace |
| D. Tree + multi-parent | S16-S22 | `2bb882e`, `c7c6f7b`, `04847f3`, `d054d63` | ✅ Broadcaster cap=10, secondary-source publish, multi-parent (>=3), RTT-biased mesh fallback, push proactivo, anycast orphan |
| E. NAT improvements | S24 | `054e776` | ✅ UPnP existente surfaceado en /api/live/log. S23 (IPv6) y S25 (birthday-paradox) postponed por complejidad |
| F. Hardening básico | S27-S29 | `6fd7af8` | ✅ S27 selftest. S29 bounds checking ya estaba en place via CSafeMemFile + size guards. S28/S30 = infraestructura externa |

**Total commits sesión**: 9 commits sustanciales, ~1100 líneas C++ + 380 líneas tooling.
**Build**: Release x64 OK en `srchybrid/x64/Release/emule.exe`.

**Bloque V3 (5K-50K viewers) — POSTPONED**:
Requiere dependencias externas vía vcpkg (libsrt 1.5.4, ISA-L para FEC, libdatachannel
para WebRTC bridge). Cada bloque (A-G) = 2-3 semanas calendario adicionales con
setup de toolchain + integración + testing. Necesita lab dedicado.

**Bloque V4 (50K-500K viewers) — RESEARCH-LEVEL**:
SVC encoding, super-relays opt-in, geographic, onion routing. Empíricamente
sin precedente en pure P2P; requiere validación en simulador/lab antes de prod.

**Próximo paso recomendado**: stress-test el build actual con `node tools/stress-test/orchestrator.js 20 <KEY>` para validar que la arquitectura V2 escala a 20+ viewers en LAN. Si OK, avanzar al setup vcpkg de libsrt para arrancar V3-S01.

### 16.1 Smoke test resultados (2026-05-15)

- **Build limpio**: `srchybrid/x64/Release/emule.exe` linka sin errores ni warnings nuevos.
- **WebServer**: arranca y responde `200 OK` en `/api/live/metrics` con todas las métricas Prometheus declaradas. Verificado en port 4798.
- **HEADLESS log**: `[TIER] Measured upload capacity` aparece al construir el manager. `[WS] BOUND OK on port N` confirma listener.
- **Pre-existing t=8s crash**: detectado durante smoke test que el binario crashea (ACCESS_VIOLATION 0xC0000005) ~8 s después del startup, INDEPENDIENTEMENTE de los flags (--headless, --metrics-port, sin args). Reproducible 3/3 veces. Esto es un bug pre-existente en el branch (probablemente AICHSyncThread o relacionado con auto-spawn de ese-server.exe en `ToggleEseServer`); no introducido por las V2 sprints.
  - Investigación recomendada (separada): correr bajo VS debugger, romper en handler de WM_TIMER con id=1972, o instrumentar AICH/ToggleEseServer.
  - El código V2 (per-peer counters, métricas, ratio enforcement, multi-parent, push proactivo) no participa en el crash — su lógica corre bajo `m_lock` desde callbacks de red que aún no han disparado a t=8 s con un broadcaster listo.
  - Crash address dump: `0x140553D20` con instrucción `cmp word ptr [rdx],0` dentro de un loop AVX2 (`vpcmpeqw ymm1,...`) — patrón inequívoco de `wcsnlen` inlineado del CRT. Significa que algún call-site pasa puntero NULL/freed a una función de longitud de wide string. Sin .pdb del entorno de build no se puede identificar el caller exacto (recomendado: build Debug, repro bajo VS debugger, mirar stack al EXCEPTION_ACCESS_VIOLATION).
  - **RESUELTO 2026-05-16 (commit `1657be7`)**: con `/MAP` en el linker + stack walk del minidump (parseo manual en PowerShell del `MINIDUMP_MEMORY_LIST` stream 5) llegamos a `CemuleDlg::OnUPnPResult` línea 3710. El bug era V2-S24: la línea `LIVE_LOG("UPNP", "...via %S", (LPCWSTR)impl->GetImplementationID())`. `GetImplementationID()` devuelve `int` (enum `UPNP_IMPL_MINIUPNPLIB=1`), no `LPCWSTR`. El cast convertía 1 en puntero literal `0x1` y `wcsnlen` reventaba leyendo desde dirección 0x1. Fix: usar `%d` con el int directamente. Bonus: clamp del overflow en `MeasureUploadCapacity` cuando `GetMaxUpload()` devuelve `UINT_MAX` (= "unlimited" en eMule prefs). Verificado: 3/3 trials sobreviven 20 s.
