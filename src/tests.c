/* Functional and negative tests for the coding layer and the protocol. */
#include "quill.h"
#include "ecc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0, passed = 0;
#define CHECK(c, msg) do { if (c) passed++; else { fails++; printf("FAIL: %s (line %d)\n", msg, __LINE__); } } while (0)

static uint32_t rs = 12345;
static uint32_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 17; rs ^= rs << 5; return rs; }

/* ---------------------------------------------------------------- coding */
static void test_ecc(void) {
    for (int t = 0; t < 200; ++t) {
        int nd = 1 + rnd() % 100, np = rnd() % 33; size_t len = 1 + rnd() % 40;
        if (np > nd) np = nd;
        uint8_t* buf = malloc((size_t)(nd + np) * len * 2);
        uint8_t *dp[255], *pp[255];
        for (int j = 0; j < nd; ++j) { dp[j] = buf + j * len; for (size_t b = 0; b < len; ++b) dp[j][b] = rnd(); }
        for (int r = 0; r < np; ++r) pp[r] = buf + (nd + r) * len;
        ecc_parity((const uint8_t* const*)dp, nd, pp, np, len);
        uint8_t* orig = buf + (nd + np) * len; memcpy(orig, buf, nd * len);
        int ne = np ? rnd() % (np + 1) : 0, miss[255], prow[255]; uint8_t used[255] = { 0 };
        for (int e = 0; e < ne; ) { int j = rnd() % nd; if (!used[j]) { used[j] = 1; miss[e++] = j; } }
        for (int e = 0; e < ne; ++e) memset(dp[miss[e]], 0xEE, len);
        /* use a random subset of parity rows */
        uint8_t pu[255] = { 0 }; const uint8_t* ps[255];
        for (int e = 0; e < ne; ) { int r = rnd() % np; if (!pu[r]) { pu[r] = 1; prow[e] = r; ps[e] = pp[r]; ++e; } }
        int rc = ecc_recover(dp, nd, miss, ne, ps, prow, np, len);
        CHECK(rc == 0 && memcmp(orig, buf, nd * len) == 0, "leaf parity recovers any e<=m missing symbols");
        free(buf);
    }
    for (int t = 0; t < 200; ++t) {
        int nf = 1 + rnd() % 128, k = 1 + rnd() % nf; size_t Dn = 1 + rnd() % 3000;
        uint8_t* D = malloc(Dn), *D2 = malloc(Dn); for (size_t i = 0; i < Dn; ++i) D[i] = rnd();
        size_t F = disp_frag_size(Dn, k); uint8_t* fr = malloc(F * nf); uint8_t have[255] = { 0 };
        disp_encode(D, Dn, k, nf, fr);
        int got = 0; while (got < k) { int j = rnd() % nf; if (!have[j]) { have[j] = 1; ++got; } }
        for (int j = 0; j < nf; ++j) if (!have[j]) memset(fr + j * F, 0x55, F);
        int rc = disp_decode(fr, have, k, nf, Dn, D2);
        CHECK(rc == 0 && memcmp(D, D2, Dn) == 0, "any k of nf fragments rebuild D");
        if (k > 1) { have[0] = have[0]; int c = 0; for (int j = 0; j < nf; ++j) if (have[j] && c++ == 0) have[j] = 0;
            CHECK(disp_decode(fr, have, k, nf, Dn, D2) != 0, "k-1 fragments are not enough"); }
        free(D); free(D2); free(fr);
    }
}

/* ------------------------------------------------------------ primitives */
static void test_sig(int id) {
    sig_key_t* k = sig_keygen(id);
    CHECK(k != NULL, "keygen");
    if (!k) return;
    size_t pkn; const uint8_t* pk = sig_pk(k, &pkn);
    uint8_t m[77]; for (int i = 0; i < 77; ++i) m[i] = (uint8_t)i;
    size_t sl = sig_info(id)->sig_len; uint8_t* s = malloc(sl + 64); size_t got = sl + 64;
    CHECK(sig_sign(k, m, 77, s, &got) == 0, "sign");
    CHECK(got <= sl, "signature length within the declared size");
    CHECK(sig_verify(id, pk, pkn, m, 77, s, got) == 0, "verify");
    m[3] ^= 1;
    CHECK(sig_verify(id, pk, pkn, m, 77, s, got) != 0, "verify rejects a modified message");
    m[3] ^= 1; s[got / 2] ^= 0x10;
    CHECK(sig_verify(id, pk, pkn, m, 77, s, got) != 0, "verify rejects a modified signature");
    free(s);
}
static void test_kem(int lvl) {
    kem_gw_t* g = kem_gw_keygen(lvl);
    uint8_t ct[KEM_MAX_CT], s1[32], s2[32];
    CHECK(kem_encaps(lvl, kem_gw_pk(g), ct, s1) == 0, "encaps");
    CHECK(kem_decaps(g, ct, s2) == 0 && !memcmp(s1, s2, 32), "hybrid secrets agree");
    ct[3] ^= 1; kem_decaps(g, ct, s2);
    CHECK(memcmp(s1, s2, 32) != 0, "modified ML-KEM ciphertext changes the secret");
    ct[3] ^= 1; ct[kem_ct_len(lvl) - 5] ^= 1; kem_decaps(g, ct, s2);
    CHECK(memcmp(s1, s2, 32) != 0, "modified X25519 share changes the secret");
}

/* ------------------------------------------------------------ end to end */
typedef struct { uint8_t* f[4096]; size_t n[4096]; int k[4096]; int cnt; } wire_t;
static void emit(void* ctx, const uint8_t* f, size_t n, int kind) {
    wire_t* w = ctx; w->f[w->cnt] = malloc(n); memcpy(w->f[w->cnt], f, n); w->n[w->cnt] = n; w->k[w->cnt] = kind; w->cnt++;
}
static void wire_free(wire_t* w) { for (int i = 0; i < w->cnt; ++i) free(w->f[i]); w->cnt = 0; }

typedef struct { int ok, fail; uint32_t lastb; int got_pt; uint8_t pt[64]; } gwev_t;
static void on_batch(void* c, uint32_t b, int nb, int ok, const uint8_t* have) { gwev_t* e = c; (void)nb; (void)have; e->lastb = b; if (ok) e->ok++; else e->fail++; }
static void on_data(void* c, uint32_t b, int i, const uint8_t* pt, size_t n) { gwev_t* e = c; (void)b; (void)i; e->got_pt++; if (n <= 64) memcpy(e->pt, pt, n); }

static sig_key_t* g_keys[SIG_COUNT];

/* runs a stream of npk packets; drop(j) says whether wire frame j is lost */
static void run(int sig, int n, int m, int k, int npk, int (*drop)(int, int, const uint8_t*), gwev_t* ev, quill_gw_t* gout, wire_t* wout) {
    quill_params_t p = { sig, KEM_MLKEM512, n, m, k, 1 };
    static kem_gw_t* kg = NULL; if (!kg) kg = kem_gw_keygen(KEM_MLKEM512);
    wire_t* w = wout; quill_dev_t d;
    int rc = quill_dev_init(&d, &p, g_keys[sig], kem_gw_pk(kg), 0xA1B2C3D4, emit, w);
    CHECK(rc == 0, "device init");
    for (int t = 0; t < npk; ++t) { uint8_t pl[20]; memset(pl, t, 20); quill_dev_send(&d, pl, 20, 0); }
    quill_dev_close(&d);
    size_t pkn; const uint8_t* pk = sig_pk(g_keys[sig], &pkn);
    quill_gw_init(gout, &p, kg, pk, pkn);
    memset(ev, 0, sizeof *ev); gout->on_batch = on_batch; gout->on_data = on_data; gout->cctx = ev;
    for (int j = 0; j < w->cnt; ++j) if (!drop || !drop(j, w->k[j], w->f[j])) quill_gw_recv(gout, w->f[j], w->n[j]);
    quill_gw_finish(gout);
    quill_dev_free(&d);
}
static int g_drop_b, g_drop_cnt, g_drop_frag;
/* drop the first g_drop_cnt data packets of batch g_drop_b */
static int drop_data(int j, int kind, const uint8_t* f) {
    (void)j; if (kind != 1) return 0;
    uint32_t b = ((uint32_t)f[5] << 24) | (f[6] << 16) | (f[7] << 8) | f[8];
    return (int)b == g_drop_b && f[9] < g_drop_cnt;
}
/* drop data frames of batch g_drop_b+1 that carry fragment index < g_drop_frag */
static int drop_frag(int j, int kind, const uint8_t* f) {
    (void)j; if (kind != 1) return 0;
    uint32_t b = ((uint32_t)f[5] << 24) | (f[6] << 16) | (f[7] << 8) | f[8];
    return (int)b == g_drop_b + 1 && f[10] && f[13] < g_drop_frag;
}

static void test_e2e(int sig) {
    wire_t* w = calloc(1, sizeof *w); quill_gw_t g; gwev_t ev;
    const int n = 16, m = 4, k = 12, N = 64;   /* 4 batches */
    run(sig, n, m, k, N, NULL, &ev, &g, w);
    CHECK(ev.ok == 4 && ev.fail == 0 && g.nr_packets == (uint32_t)N, "no loss: every batch verified");
    CHECK(g.rx_data == (uint32_t)N, "no loss: every packet authenticated at once");
    quill_gw_free(&g); wire_free(w);

    g_drop_b = 1; g_drop_cnt = m;
    run(sig, n, m, k, N, drop_data, &ev, &g, w);
    CHECK(ev.ok == 4 && g.nr_packets == (uint32_t)(N - m), "m lost packets in a batch: batch still verified");
    quill_gw_free(&g); wire_free(w);

    /* the lost packets of batch 1 also carry fragments of batch 0: with
       k = 10 batch 0 survives 5 lost fragments, so only batch 1 fails */
    g_drop_cnt = m + 1;
    run(sig, n, m, 10, N, drop_data, &ev, &g, w);
    CHECK(ev.ok == 3 && ev.fail == 1, "m+1 lost packets: only that batch fails");
    quill_gw_free(&g); wire_free(w);
    g_drop_cnt = m + 1;
    run(sig, n, m, k, N, drop_data, &ev, &g, w);
    CHECK(ev.ok == 2 && ev.fail == 2, "m+1 lost packets that also carry n-k+1 fragments: both batches fail");
    quill_gw_free(&g); wire_free(w);

    g_drop_b = 0; g_drop_frag = n - k;
    run(sig, n, m, k, N, drop_frag, &ev, &g, w);
    CHECK(ev.ok == 4, "n-k lost fragments: authenticator rebuilt");
    quill_gw_free(&g); wire_free(w);

    g_drop_frag = n - k + 1;                  /* m = 6 so that batch 1 itself survives */
    run(sig, n, 6, k, N, drop_frag, &ev, &g, w);
    CHECK(ev.ok == 3 && ev.fail == 1, "n-k+1 lost fragments: that batch fails");
    quill_gw_free(&g); wire_free(w);
    free(w);
}

static int tamper_idx = -1, tamper_off = 0;
static int tamper(int j, int kind, const uint8_t* f) {
    (void)kind; if (j == tamper_idx) ((uint8_t*)f)[tamper_off] ^= 0x01; return 0;
}
static void test_attacks(int sig) {
    wire_t* w = calloc(1, sizeof *w); quill_gw_t g; gwev_t ev;
    /* frame 0 init, frames 1..16 batch 0, 17..32 batch 1 (carry fragments of batch 0) */
    tamper_idx = 3; tamper_off = QUILL_HDR_DATA + 2;           /* ciphertext of batch 0 packet 2 */
    run(sig, 16, 4, 12, 32, tamper, &ev, &g, w);
    CHECK(g.rx_auth_fail == 1 && ev.ok == 2, "modified ciphertext rejected at once; batch verifiable as a loss");
    quill_gw_free(&g); wire_free(w);

    tamper_idx = 18; tamper_off = QUILL_HDR_DATA + 1;          /* encrypted fragment byte of D_0 */
    run(sig, 16, 4, 12, 32, tamper, &ev, &g, w);
    CHECK(g.rx_auth_fail == 1 && ev.ok == 2 && ev.fail == 0, "modified fragment rejected with its frame: no decoder pollution");
    quill_gw_free(&g); wire_free(w);

    /* forged AUX fragment (urgent path) is rejected */
    {
        quill_params_t p = { sig, KEM_MLKEM512, 16, 4, 12, 1 };
        kem_gw_t* kg = kem_gw_keygen(KEM_MLKEM512); quill_dev_t d;
        quill_dev_init(&d, &p, g_keys[sig], kem_gw_pk(kg), 9, emit, w);
        uint8_t pl[8] = { 0 }; for (int t = 0; t < 3; ++t) quill_dev_send(&d, pl, 8, t == 2);
        size_t pkn; const uint8_t* pk = sig_pk(g_keys[sig], &pkn);
        quill_gw_init(&g, &p, kg, pk, pkn); memset(&ev, 0, sizeof ev); g.on_batch = on_batch; g.cctx = &ev;
        int forged = 0;
        for (int j = 0; j < w->cnt; ++j) { if (w->k[j] == 2 && !forged) { w->f[j][QUILL_HDR_AUX + 3] ^= 1; forged = 1; } quill_gw_recv(&g, w->f[j], w->n[j]); }
        CHECK(g.rx_auth_fail == 1 && ev.ok == 1, "forged AUX fragment rejected; batch verified from the rest");
        quill_dev_free(&d); quill_gw_free(&g); wire_free(w);
    }

    tamper_idx = 0; tamper_off = 7;                           /* init frame */
    run(sig, 16, 4, 12, 32, tamper, &ev, &g, w);
    CHECK(g.ready == 0 && g.rx_data == 0, "modified INIT frame: session refused");
    quill_gw_free(&g); wire_free(w);

    /* replay of a data frame into a later position is rejected: AAD/nonce bind (b, i) */
    tamper_idx = -1;
    run(sig, 16, 4, 12, 32, NULL, &ev, &g, w);
    uint8_t* f = malloc(w->n[2]); memcpy(f, w->f[2], w->n[2]);
    f[9] = 5;                                                  /* claim another index */
    int before = (int)g.rx_auth_fail; quill_gw_recv(&g, f, w->n[2]);
    CHECK((int)g.rx_auth_fail == before + 1, "relabelled frame rejected");
    free(f);
    quill_gw_free(&g); wire_free(w); free(w);
}

static void test_evidence(int sig) {
    wire_t* w = calloc(1, sizeof *w); quill_gw_t g; gwev_t ev;
    run(sig, 16, 4, 12, 37, NULL, &ev, &g, w);          /* last batch has 5 packets */
    /* record 7 of batch 1: frame index 1 + 16 + 7 */
    int fi = 1 + 16 + 7; const uint8_t* fr = w->f[fi];
    size_t F = fr[10] ? quill_frag_len(g.p.sig, fr[10], fr[11], fr[12]) : 0;
    const uint8_t* ct = fr + QUILL_HDR_DATA; size_t ctn = w->n[fi] - QUILL_HDR_DATA;
    quill_evidence_t e;
    int rc = quill_gw_evidence(&g, 1, 7, fr, ct, ctn, &e);
    if (rc) { CHECK(0, "evidence available for a verified batch"); goto out; }
    size_t pkn; const uint8_t* pk = sig_pk(g_keys[sig], &pkn);
    CHECK(quill_audit(sig, pk, pkn, &e) == 0, "per-record evidence verifies (third party)");
    CHECK(e.plen == 4, "path of a 16-leaf batch has 4 nodes");
    uint8_t key[32]; uint8_t* pt = malloc(ctn);
    quill_gw_packet_key(&g, 1, 7, key);
    CHECK(quill_audit_open(&e, key, pt) == 0 && pt[F] == 16 + 7, "disclosed packet key opens exactly that record");
    uint8_t key2[32]; quill_gw_packet_key(&g, 1, 8, key2);
    CHECK(quill_audit_open(&e, key2, pt) != 0, "key of another record fails the key commitment");
    free(pt);
    uint8_t* bad = malloc(ctn); memcpy(bad, ct, ctn); bad[0] ^= 1; e.ct = bad;
    CHECK(quill_audit(sig, pk, pkn, &e) != 0, "evidence for a modified ciphertext fails");
    free(bad); e.ct = ct;
    e.i = 6;
    CHECK(quill_audit(sig, pk, pkn, &e) != 0, "evidence moved to another index fails");
out:
    quill_gw_free(&g); wire_free(w); free(w);
}

static void test_urgent(int sig) {
    quill_params_t p = { sig, KEM_MLKEM512, 16, 4, 12, 1 };
    kem_gw_t* kg = kem_gw_keygen(KEM_MLKEM512);
    wire_t* w = calloc(1, sizeof *w); quill_dev_t d; quill_gw_t g; gwev_t ev;
    quill_dev_init(&d, &p, g_keys[sig], kem_gw_pk(kg), 7, emit, w);
    uint8_t pl[8] = { 0 };
    for (int t = 0; t < 5; ++t) quill_dev_send(&d, pl, 8, 0);
    int before = w->cnt;
    quill_dev_send(&d, pl, 8, 1);                          /* alarm: closes batch 0 with 6 packets */
    int aux = 0; for (int j = before; j < w->cnt; ++j) aux += w->k[j] == 2;
    CHECK(aux == 16, "urgent packet: its authenticator leaves at once (16 AUX fragments)");
    size_t pkn; const uint8_t* pk = sig_pk(g_keys[sig], &pkn);
    quill_gw_init(&g, &p, kg, pk, pkn); memset(&ev, 0, sizeof ev); g.on_batch = on_batch; g.cctx = &ev;
    for (int j = 0; j < w->cnt; ++j) quill_gw_recv(&g, w->f[j], w->n[j]);
    CHECK(ev.ok == 1 && g.nr_packets == 6, "urgent batch verified before the next packet");
    quill_dev_free(&d); quill_gw_free(&g); wire_free(w); free(w);
}

/* m and k change from batch to batch (adaptive operation) */
static void test_adaptive(int sig) {
    quill_params_t p = { sig, KEM_MLKEM512, 16, 4, 12, 1 };
    kem_gw_t* kg = kem_gw_keygen(KEM_MLKEM512);
    wire_t* w = calloc(1, sizeof *w); quill_dev_t d; quill_gw_t g; gwev_t ev;
    quill_dev_init(&d, &p, g_keys[sig], kem_gw_pk(kg), 3, emit, w);
    static const int M[4] = { 4, 9, 0, 15 }, K[4] = { 6, 6, 16, 3 };
    uint8_t pl[12] = { 0 };
    for (int b = 0; b < 4; ++b) { CHECK(quill_dev_set_mk(&d, M[b], K[b]) == 0, "set m and k"); for (int t = 0; t < 16; ++t) quill_dev_send(&d, pl, 12, 0); }
    CHECK(quill_dev_set_mk(&d, 3, 17) != 0 && quill_dev_set_mk(&d, -1, 4) != 0, "invalid m or k refused");
    quill_dev_close(&d);
    size_t pkn; const uint8_t* pk = sig_pk(g_keys[sig], &pkn);
    /* drop 9 packets of batch 1 (m = 9) and 10 frames of batch 2, which carry fragments of batch 1 (k = 6) */
    quill_gw_init(&g, &p, kg, pk, pkn); memset(&ev, 0, sizeof ev); g.on_batch = on_batch; g.cctx = &ev;
    for (int j = 0; j < w->cnt; ++j) {
        int drop = (j >= 1 + 16 && j < 1 + 16 + 9) || (j >= 1 + 32 && j < 1 + 32 + 10);
        if (!drop) quill_gw_recv(&g, w->f[j], w->n[j]);
    }
    quill_gw_finish(&g);
    CHECK(ev.ok == 3 && ev.fail == 1, "per-batch m and k: batch 1 survives 9 losses with m = 9; batch 2 (m = 0) fails");
    quill_dev_free(&d); quill_gw_free(&g); wire_free(w); free(w);
}

int main(int argc, char** argv) {
    crypto_init();
    int only = argc > 1 ? atoi(argv[1]) : -1;
    test_ecc();
    printf("coding tests done (%d passed, %d failed)\n", passed, fails);
    test_kem(KEM_MLKEM512); test_kem(KEM_MLKEM768);
    for (int s = 0; s < SIG_COUNT; ++s) {
        if (only >= 0 && s != only) continue;
        int f0 = fails;
        g_keys[s] = sig_keygen(s);
        test_sig(s);
        test_e2e(s);
        test_attacks(s);
        test_evidence(s);
        test_urgent(s);
        test_adaptive(s);
        printf("%-24s %s\n", sig_info(s)->name, fails == f0 ? "ok" : "FAILED");
    }
    printf("\n%d checks passed, %d failed\n", passed, fails);
    return fails ? 1 : 0;
}
