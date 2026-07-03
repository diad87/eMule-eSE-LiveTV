/* SPDX-License-Identifier: MIT
 *
 * libreach — reach.h: the public C ABI (KEP-1 reference library, thesis §13).
 *
 * This header is pure C (compiles as C and C++) so Rust/Go/Node/JNI reach it
 * by FFI, exactly like `utp.h`. Design invariants enforced by this surface:
 *
 *   - Total opacity: the host only ever holds `reach_context*` (opaque) and
 *     `reach_peer_id` (an integer handle the library owns). No internal struct
 *     is exposed.
 *   - Pure Inversion of Control: the library opens no sockets, spawns no
 *     threads and knows nothing of Kad. Every side effect is a host callback.
 *   - Single-thread discipline: no internal mutex. The host calls libreach
 *     from ONE thread (its network pump). Readers on other threads (e.g. a
 *     Node WebServer) consume the immutable `reach_stats` snapshot copied out
 *     after `reach_tick`.
 *   - No dangling pointers: the library NEVER stores a host object pointer.
 *     The only host pointer it keeps is the context-level `host` cookie, whose
 *     lifetime the host guarantees outlives the context. Per-peer correlation
 *     is the generation-counted `reach_peer_id`; the host maps that to its own
 *     CUpDownClient at call time.
 */
#ifndef LIBREACH_REACH_H
#define LIBREACH_REACH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define REACH_ABI_VERSION 1u
#define REACH_KADID_SIZE  16

/* Opaque engine handle. */
typedef struct reach_context reach_context;

/* Library-owned, generation-counted peer handle. 0 is never valid. */
typedef uint64_t reach_peer_id;
#define REACH_PEER_NONE ((reach_peer_id)0)

/* A network endpoint the host must route. The host owns the dual-stack
 * (v4/v6) socket; libreach only describes where a datagram should go. */
typedef struct reach_endpoint {
    uint8_t  family;     /* 4 = IPv4, 6 = IPv6, 0 = none                       */
    uint8_t  reserved;   /* must be 0                                          */
    uint16_t port;       /* host byte order; host adapts to its socket layer   */
    uint8_t  addr[16];   /* address octets; first 4 used when family == 4      */
} reach_endpoint;

typedef enum reach_status {
    REACH_OK = 0,
    REACH_ERR_NULL_ARG,
    REACH_ERR_BAD_ABI,
    REACH_ERR_NO_MEM,
    REACH_ERR_STALE_PEER,    /* handle refers to a closed / reused slot        */
    REACH_ERR_UNKNOWN_PEER,
    REACH_ERR_BAD_ARG
} reach_status;

/* How a connect attempt resolved (Appendix B). */
typedef enum reach_result {
    REACH_RESULT_PENDING = 0,
    REACH_RESULT_CONNECTED,  /* a cascade layer succeeded (host has transport) */
    REACH_RESULT_CLASSIC,    /* all eSE layers inapplicable → use upstream path*/
    REACH_RESULT_ABORTED     /* peer closed before resolution                  */
} reach_result;

/* Connection cascade layers (Appendix B), in attempt order. */
typedef enum reach_layer {
    REACH_LAYER_NONE      = -1,
    REACH_LAYER_DIRECT_V6 = 0,
    REACH_LAYER_DIRECT_V4 = 1,
    REACH_LAYER_CALLBACK  = 2,
    REACH_LAYER_PUNCH_2W  = 3,
    REACH_LAYER_PUNCH_3W  = 4,
    REACH_LAYER_RELAY     = 5,
    REACH_LAYER_CLASSIC   = 6   /* terminal fallback; never worse than upstream */
} reach_layer;
#define REACH_LAYER_COUNT (REACH_LAYER_CLASSIC + 1)

/* ── Host callbacks (the IoC seam) ──────────────────────────────────────────
 * EVERY callback's first argument is the context-level `host` cookie passed to
 * reach_context_create — never a per-peer host pointer. When a callback carries
 * a `reach_peer_id`, the host resolves it to its own object via its own map at
 * call time, so a peer the host already destroyed simply maps to nothing and
 * the host drops the work. This is what makes the boundary UAF-free.
 *
 * All callbacks are invoked synchronously on the thread that called into
 * libreach. They may call reach_peer_close re-entrantly (reclaim is deferred
 * until the outermost libreach call unwinds). They must not call
 * reach_context_destroy re-entrantly. */
typedef struct reach_host_callbacks {
    uint32_t abi_version;    /* must equal REACH_ABI_VERSION */
    uint32_t reserved;

    /* Send a raw UDP datagram to `dst` on the host's Kad UDP socket.
     * Return 0 on enqueue, non-zero on failure. */
    int (*send_udp)(void* host, reach_peer_id peer,
                    const reach_endpoint* dst,
                    const uint8_t* data, size_t len);

    /* A cascade layer decided `dst` is reachable for `peer`; the host should
     * open its real transport (uTP/TCP) and later call
     * reach_on_transport_result. Return 0 if the attempt was started. */
    int (*open_transport)(void* host, reach_peer_id peer,
                          reach_layer layer, const reach_endpoint* dst);

    /* Forward opaque libreach signaling to a rendezvous node `via` (3-way
     * punch) through the host's own Kad. The host does not interpret payload. */
    int (*signal_via_rdv)(void* host, reach_peer_id peer,
                          const reach_endpoint* via,
                          const uint8_t* payload, size_t len);

    /* Fill `out[0..n)` with cryptographically secure random bytes (host CSPRNG,
     * e.g. CryptoPP AutoSeededRandomPool). Return 0 on success. */
    int (*csprng)(void* host, uint8_t* out, size_t n);

    /* Monotonic milliseconds (host GetTickCount / steady_clock). */
    uint64_t (*clock_ms)(void* host);

    /* Optional. A connect resolved; host may now wire its CUpDownClient. */
    void (*on_result)(void* host, reach_peer_id peer,
                      reach_result result, reach_layer via);

    /* Optional. Structured log: level 0=info, 1=warn, 2=error. */
    void (*log)(void* host, int level, const char* msg);
} reach_host_callbacks;

/* ── Configuration ─────────────────────────────────────────────────────────*/
typedef struct reach_config {
    uint32_t abi_version;                       /* must equal REACH_ABI_VERSION */
    uint16_t my_cap_flags;                      /* KAD_CAP_* bits we advertise  */
    uint16_t reserved;
    uint32_t connect_deadline_ms;               /* 0 → library default          */
    uint32_t layer_budget_ms[REACH_LAYER_COUNT];/* per-layer budget; 0 → default*/
    uint32_t max_peers;                         /* 0 → library default          */
} reach_config;

/* ── Lifecycle ─────────────────────────────────────────────────────────────
 * `host` is the opaque cookie handed back to every callback. Its lifetime MUST
 * outlive the returned context. Returns NULL on bad ABI / null callbacks /
 * allocation failure. */
reach_context* reach_context_create(const reach_host_callbacks* cb,
                                    const reach_config* cfg,
                                    void* host);
void           reach_context_destroy(reach_context* ctx);

/* Drive the engine (call ~1 Hz, or faster). Invokes callbacks synchronously.
 * Returns the number of peers still pending, or a negative reach_status on a
 * null context. */
int reach_tick(reach_context* ctx);

/* Begin connecting to a peer identified by its 16-byte NodeID. `peer_vector`
 * (len bytes) is the peer's TAG_REACH payload from a Kad search, or NULL to
 * project from the classic registration. Idempotent per NodeID: a repeat
 * connect to an already-active NodeID returns the same handle. */
reach_status reach_connect(reach_context* ctx,
                           const uint8_t nodeid[REACH_KADID_SIZE],
                           const uint8_t* peer_vector, size_t vector_len,
                           reach_peer_id* out_peer);

/* Supply the peer's PRIMARY transport endpoints — its own v4 and/or v6 address,
 * which the host holds from the classic Kad contact (TAG_SOURCEIP / TAG 0x66) but
 * which the TAG_REACH vector does NOT carry. Call after reach_connect and before
 * the cascade actuates: the DIRECT_V6 / DIRECT_V4 / PUNCH_2W rungs need it; the
 * rdv-mediated rungs (PUNCH_3W / RELAY) use anchors already in the vector.
 *
 * Pass NULL (or a family-0 endpoint) for an absent family — the cascade then
 * SKIPS the rung that needed it, gracefully. The latest call wins (idempotent).
 * Additive to ABI v1: a host that never calls it loses only the direct rungs and
 * still degrades to CLASSIC, never to an error. */
reach_status reach_set_candidates(reach_context* ctx, reach_peer_id peer,
                                  const reach_endpoint* v4,
                                  const reach_endpoint* v6);

/* Host MUST call this from its CUpDownClient teardown (or to cancel a connect).
 * Safe inside a callback (reclaim deferred). Stale/unknown ids return
 * REACH_ERR_STALE_PEER harmlessly — closing twice never crashes. */
reach_status reach_peer_close(reach_context* ctx, reach_peer_id peer);

/* Feed an inbound libreach-relevant UDP packet the host received. `opcode` is
 * the host wire opcode byte; `payload` is the bytes after it. */
reach_status reach_on_udp(reach_context* ctx,
                          const reach_endpoint* from, uint8_t opcode,
                          const uint8_t* payload, size_t len);

/* Host reports the outcome of an open_transport request (connected != 0). */
reach_status reach_on_transport_result(reach_context* ctx, reach_peer_id peer,
                                       int connected);

/* ── Immutable snapshot (cross-thread readers consume this) ────────────────*/
typedef struct reach_stats {
    uint32_t peers_active;
    uint32_t peers_pending;
    uint64_t connects_total;
    uint64_t resolved_connected;
    uint64_t resolved_classic;
    uint64_t udp_sent;
    uint64_t udp_recv;
} reach_stats;

/* Copy current counters into `out`. Lock-free value copy; the host calls it on
 * its network thread (typically right after reach_tick) and hands the result
 * to other threads. */
reach_status reach_get_stats(const reach_context* ctx, reach_stats* out);

const char* reach_status_str(reach_status s);
uint32_t    reach_abi_version(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LIBREACH_REACH_H */
