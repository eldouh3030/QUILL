/* Loss-tolerant, post-quantum non-repudiation for IoMT sensor streams.

   Device -> gateway. Every packet is encrypted and authenticated at once with
   a per-packet AES-256-GCM key (immediate, symmetric authenticity). Packets
   are grouped in batches of n; the device signs the Merkle root of the batch
   with a post-quantum signature. The authenticator of batch b,
       D_b = sigma_b || m parity symbols of the n leaf hashes,
   is erasure-coded into n fragments that ride on the packets of batch b+1
   (no buffering, no added clinical latency); any k fragments rebuild D_b and
   any batch with at most m lost packets becomes verifiable.

   Wire format
     INIT : 0x00 | sid(4) | kem_ct | sig_init
     DATA : 0x01 | sid(4) | b(4) | i(1) | fn(1) | fj(1) | GCM(frag(F) || payload) || tag(16)
     AUX  : 0x02 | sid(4) | b(4) | fn(1) | fj(1) | GCM(frag(F)) || tag(16)
   fn = size of the batch the fragment belongs to (0: no fragment), fj = index.
   In a DATA frame of batch b the fragment belongs to batch b-1. The fragment
   travels inside the AEAD plaintext, so an outsider can neither read nor
   inject fragments (no pollution of the erasure decoder); the 12-byte header
   is the associated data.                                                    */
#ifndef QUILL_H
#define QUILL_H
#include <stdint.h>
#include <stddef.h>
#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QUILL_LEAF      32
#define QUILL_MAX_N     128
#define QUILL_HDR_DATA  12
#define QUILL_HDR_AUX   11
#define QUILL_TAG       16

typedef struct {
    int sig;          /* enum sig_id */
    int kem;          /* KEM_MLKEM512 / KEM_MLKEM768 */
    int n;            /* batch size */
    int m;            /* leaf parity symbols (tolerated losses per batch) */
    int k;            /* fragments needed to rebuild D (of n) */
    int urgent_aux;   /* 1: an urgent packet closes the batch and its D is sent at once in AUX frames */
} quill_params_t;

typedef void (*quill_emit_fn)(void* ctx, const uint8_t* frame, size_t len, int kind /* 0 init 1 data 2 aux */);

/* size of D for a batch of nb packets */
size_t quill_D_len(const quill_params_t* p, int nb);
int    quill_m_eff(const quill_params_t* p, int nb);
size_t quill_frag_len(const quill_params_t* p, int nb);

/* ------------------------------------------------------------------ device */
typedef struct {
    quill_params_t p;
    sig_key_t* sk;
    uint32_t sid;
    uint8_t th[32];
    uint8_t ck[32];        /* chain key of the current batch */
    uint8_t kb[32];        /* batch key */
    uint32_t b;            /* current batch number */
    int i;                 /* next packet index in batch */
    uint8_t leaf[QUILL_MAX_N][QUILL_LEAF];
    /* pending authenticator of the previous batch, dispersed into fragments */
    uint8_t* frag; size_t F; int fn; uint32_t fb; int fsent;
    uint8_t* D; size_t Dcap;
    quill_emit_fn emit; void* ectx;
    uint8_t* buf; size_t bufcap;
    uint8_t* pt; size_t ptcap;
    uint8_t kb_prev[32];   /* batch key of the batch whose authenticator is pending */
    /* statistics */
    uint64_t bytes_data, bytes_aux, bytes_init, payload_bytes;
    uint32_t packets, aux_frames, signatures;
} quill_dev_t;

int  quill_dev_init(quill_dev_t* d, const quill_params_t* p, sig_key_t* sk,
                  const uint8_t* gw_pk, uint32_t sid, quill_emit_fn emit, void* ectx);
int  quill_dev_send(quill_dev_t* d, const uint8_t* payload, size_t len, int urgent);
int  quill_dev_close(quill_dev_t* d);      /* ends the session, flushes everything */
void quill_dev_free(quill_dev_t* d);

/* ----------------------------------------------------------------- gateway */
#define QUILL_RING 4
typedef struct {
    uint32_t b; int used;
    int nb;                               /* batch size once known (fn), else 0 */
    uint8_t have[QUILL_MAX_N];
    uint8_t leaf[QUILL_MAX_N][QUILL_LEAF];
    uint8_t kc[QUILL_MAX_N][32];
    uint8_t fhave[QUILL_MAX_N];
    uint8_t* frag; size_t F; int nfr;
    int state;                            /* 0 open, 1 verified, -1 failed */
    uint8_t root[32];
    uint8_t* sig; size_t siglen;
} quill_gw_batch_t;

typedef struct {
    quill_params_t p;
    kem_gw_t* kem;
    const uint8_t* dev_pk; size_t dev_pklen;
    uint32_t sid; int ready;
    uint8_t th[32];
    uint8_t ck0[32];
    uint32_t ck_b; uint8_t ck[32];        /* cached chain position */
    quill_gw_batch_t ring[QUILL_RING];
    /* callbacks */
    void (*on_data)(void* ctx, uint32_t b, int i, const uint8_t* pt, size_t n);
    void (*on_batch)(void* ctx, uint32_t b, int nb, int ok, const uint8_t* have);
    void* cctx;
    /* statistics */
    uint32_t rx_data, rx_auth_fail, batches_ok, batches_fail, nr_packets;
} quill_gw_t;

int  quill_gw_init(quill_gw_t* g, const quill_params_t* p, kem_gw_t* kem, const uint8_t* dev_pk, size_t dev_pklen);
int  quill_gw_recv(quill_gw_t* g, const uint8_t* f, size_t len);
void quill_gw_finish(quill_gw_t* g);       /* settle open batches at end of stream */
void quill_gw_free(quill_gw_t* g);

/* --------------------------------------------------- evidence and auditing */
/* Per-record evidence for an electronic health record: everything a third
   party needs to check that the device produced a given ciphertext, and, when
   the per-packet key is disclosed, its plaintext. */
typedef struct {
    uint8_t th[32]; uint32_t b; int nb; int i;
    uint8_t hdr[QUILL_HDR_DATA];          /* frame header (associated data) */
    uint8_t kc[32];
    const uint8_t* ct; size_t ctlen;      /* ciphertext || tag (covers fragment and payload) */
    uint8_t path[8][32]; int plen;
    const uint8_t* sig; size_t siglen;
} quill_evidence_t;

/* gateway: build the Merkle path for record i of a verified batch */
int quill_gw_evidence(quill_gw_t* g, uint32_t b, int i, const uint8_t* hdr, const uint8_t* ct, size_t ctlen, quill_evidence_t* ev);
/* gateway: per-packet key for selective disclosure */
int quill_gw_packet_key(quill_gw_t* g, uint32_t b, int i, uint8_t key[32]);
/* anyone: 0 if the evidence is valid under the device public key */
int quill_audit(int sig, const uint8_t* dev_pk, size_t pklen, const quill_evidence_t* ev);
/* auditor holding a disclosed packet key: checks the key commitment and decrypts
   (pt receives fragment || payload; the payload starts after the fragment
   length given by hdr[10]) */
int quill_audit_open(const quill_evidence_t* ev, const uint8_t key[32], uint8_t* pt);

/* shared helpers (also used by the baselines) */
void quill_leaf(const uint8_t th[32], uint32_t b, int i, const uint8_t kc[32], const uint8_t* ct, size_t ctlen, uint8_t out[32]);
void quill_root(const uint8_t th[32], uint32_t b, uint8_t (*leaf)[QUILL_LEAF], int nb, uint8_t out[32]);
size_t quill_batch_msg(const uint8_t th[32], uint32_t b, int nb, const uint8_t root[32], uint8_t* out);

#ifdef __cplusplus
}
#endif
#endif
