/* Device-side operations, built for an ARM Cortex-M4F and executed in an
   instruction-level emulator by run.c. Each op_* function is one measured
   unit; setup() provisions long-term keys and is not measured.
   The protocol code is the same source as the host build (src/). */
#include "crypto.h"
#include "ecc.h"
#include "quill.h"
#include <string.h>

extern void fw_heap_set_mark(void);
extern void fw_heap_reset(void);

volatile int g_status;
volatile uint32_t g_len = 16;       /* payload bytes */
volatile uint32_t g_n = 32;         /* batch size */
volatile uint32_t g_m = 8;          /* leaf parity */
volatile uint32_t g_k = 24;         /* fragment threshold */
volatile uint32_t g_sig = 0;        /* signature scheme for op_batch / op_sign */

static uint8_t msg[78];
static uint8_t sigbuf[17088 + 64];
static size_t siglen;
static sig_key_t* keys[SIG_COUNT];
static kem_gw_t* gw512; static kem_gw_t* gw768;
static uint8_t gw_pk512[KEM_MAX_PK], gw_pk768[KEM_MAX_PK];
static uint8_t ct[KEM_MAX_CT], ss[32];
static uint8_t payload[256];
static quill_dev_t dev;

void heap_reset(void) { fw_heap_reset(); }

#define CHK(x) do { int _r = (x); if (_r != 0) { g_status = _r; return; } } while (0)

static void sink(void* c, const uint8_t* f, size_t n, int kind) { (void)c; (void)f; (void)n; (void)kind; }

void setup(void) {
    g_status = 0;
    for (unsigned i = 0; i < sizeof msg; ++i) msg[i] = (uint8_t)(i * 3 + 1);
    for (unsigned i = 0; i < sizeof payload; ++i) payload[i] = (uint8_t)i;
    CHK(crypto_init());
    gf_init();
    gw512 = kem_gw_keygen(KEM_MLKEM512); gw768 = kem_gw_keygen(KEM_MLKEM768);
    if (!gw512 || !gw768) { g_status = -10; return; }
    memcpy(gw_pk512, kem_gw_pk(gw512), kem_pk_len(KEM_MLKEM512));
    memcpy(gw_pk768, kem_gw_pk(gw768), kem_pk_len(KEM_MLKEM768));
    static const int ids[] = { SIG_MLDSA44, SIG_FALCON512, SIG_SPHINCS128S, SIG_SPHINCS128F, SIG_LMS, SIG_ED25519, SIG_MLDSA44_REF };
    for (unsigned t = 0; t < sizeof ids / sizeof *ids; ++t) {
        keys[ids[t]] = sig_keygen(ids[t]);
        if (!keys[ids[t]]) { g_status = -20 - (int)ids[t]; return; }
    }
    fw_heap_set_mark();
}

/* ------------------------------------------------------------ primitives */
void op_sha256(void)  { uint8_t h[32]; h256(payload, g_len, h); }
void op_hkdf(void)    { uint8_t k[32]; CHK(hkdf(ss, 32, NULL, 0, msg, 8, k, 32)); }
void op_gcm(void)     { static uint8_t out[256 + 16]; uint8_t iv[12] = { 0 }; CHK(gcm_enc(ss, iv, msg, 10, payload, g_len, out)); }
void op_hybrid512(void) { CHK(kem_encaps(KEM_MLKEM512, gw_pk512, ct, ss)); }
void op_hybrid768(void) { CHK(kem_encaps(KEM_MLKEM768, gw_pk768, ct, ss)); }

static void do_sign(int id) { siglen = sizeof sigbuf; CHK(sig_sign(keys[id], msg, sizeof msg, sigbuf, &siglen)); }
void op_sign_mldsa44(void)    { do_sign(SIG_MLDSA44); }
void op_sign_mldsa44ref(void) { do_sign(SIG_MLDSA44_REF); }
void op_sign_falcon512(void)  { do_sign(SIG_FALCON512); }
void op_sign_sphincs128s(void){ do_sign(SIG_SPHINCS128S); }
void op_sign_sphincs128f(void){ do_sign(SIG_SPHINCS128F); }
void op_sign_lms(void)        { do_sign(SIG_LMS); }
void op_sign_ed25519(void)    { do_sign(SIG_ED25519); }
/* verification on the device is not needed by the protocol; measured for reference */
static uint8_t vsig[SIG_COUNT][17088]; static size_t vlen[SIG_COUNT];
void prep_verify(void) {
    for (int id = 0; id < SIG_COUNT; ++id) { if (!keys[id]) continue; vlen[id] = sizeof vsig[id];
        if (sig_sign(keys[id], msg, sizeof msg, vsig[id], &vlen[id])) { g_status = -1; return; } }
    fw_heap_set_mark();
}
static void do_ver(int id) { size_t pkn; const uint8_t* pk = sig_pk(keys[id], &pkn);
    if (sig_verify(id, pk, pkn, msg, sizeof msg, vsig[id], vlen[id])) g_status = -2; }
void op_verify_mldsa44(void)   { do_ver(SIG_MLDSA44); }
void op_verify_falcon512(void) { do_ver(SIG_FALCON512); }
void op_verify_lms(void)       { do_ver(SIG_LMS); }
void op_verify_ed25519(void)   { do_ver(SIG_ED25519); }
void op_verify_sphincs128s(void) { do_ver(SIG_SPHINCS128S); }

/* ------------------------------------------------------ protocol pieces */
static uint8_t leaves[QUILL_MAX_N][QUILL_LEAF];
void op_leaf(void) {                       /* per-packet key, key commitment, leaf hash */
    uint8_t th[32] = { 1 }, kc[32]; static uint8_t c[256 + 16];
    memset(c, 7, g_len + 16);
    quill_leaf(th, 1, 3, kc, c, g_len + 16, leaves[0]);
}
void op_merkle(void) { uint8_t th[32] = { 1 }, root[32]; quill_root(th, 1, leaves, (int)g_n, root); }
void op_parity(void) {
    static uint8_t par[64][QUILL_LEAF];
    const uint8_t* lp[QUILL_MAX_N]; uint8_t* pp[64];
    for (uint32_t j = 0; j < g_n; ++j) lp[j] = leaves[j];
    for (uint32_t r = 0; r < g_m; ++r) pp[r] = par[r];
    ecc_parity(lp, (int)g_n, pp, (int)g_m, QUILL_LEAF);
}
static uint8_t Dbuf[17088 + 64 * 32], frbuf[128 * 1100];
void op_disperse(void) {                   /* D = signature || m parity leaves */
    size_t Dn = sig_info((int)g_sig)->sig_len + g_m * 32;
    disp_encode(Dbuf, Dn, (int)g_k, (int)g_n, frbuf);
}
void op_hkdf_expand(void) { uint8_t k[32]; CHK(hkdf_expand(ss, msg, 9, k, 32)); }

/* one ordinary packet (the batch is never closed here) */
void prep_session(void) {
    quill_params_t p = { (int)g_sig, KEM_MLKEM512, (int)g_n, (int)g_m, (int)g_k, 0 };
    quill_dev_free(&dev);
    if (quill_dev_init(&dev, &p, keys[g_sig], gw_pk512, 1, sink, 0)) { g_status = -3; return; }
    fw_heap_set_mark();
}
/* fill one batch so that the following packets carry authenticator fragments */
static int saved_fn;
void prep_fill(void) {
    for (uint32_t t = 0; t < g_n; ++t) CHK(quill_dev_send(&dev, payload, g_len, 0));
    saved_fn = dev.fn;
    CHK(quill_dev_send(&dev, payload, g_len, 0));   /* grows the frame buffers before the mark */
    fw_heap_set_mark();
}
/* one ordinary packet carrying a fragment (the batch is never closed here) */
void op_packet(void) {
    if (dev.i >= dev.p.n - 1) dev.i = 0;   /* stay inside the batch */
    if (saved_fn && (!dev.fn || dev.fsent >= dev.p.n - 1)) { dev.fn = saved_fn; dev.fsent = 0; }
    CHK(quill_dev_send(&dev, payload, g_len, 0));
}
/* a whole batch: n packets including the close (sign + parity + dispersal) */
void op_batch(void) {
    for (uint32_t t = 0; t < g_n; ++t) CHK(quill_dev_send(&dev, payload, g_len, 0));
}
/* session set-up on the device: hybrid encapsulation + INIT signature */
void op_session(void) {
    quill_params_t p = { (int)g_sig, KEM_MLKEM512, (int)g_n, (int)g_m, (int)g_k, 0 };
    quill_dev_t d2;
    CHK(quill_dev_init(&d2, &p, keys[g_sig], gw_pk512, 2, sink, 0));
}
