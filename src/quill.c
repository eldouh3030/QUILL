#include "quill.h"
#include "ecc.h"
#include <string.h>
#include <stdlib.h>

static void put32(uint8_t* p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static uint32_t get32(const uint8_t* p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

/* ------------------------------------------------------------- parameters */
int quill_m_eff(const quill_params_t* p, int nb) { return p->m < nb ? p->m : nb; }
size_t quill_D_len(const quill_params_t* p, int nb) {
    return sig_info(p->sig)->sig_len + (size_t)quill_m_eff(p, nb) * QUILL_LEAF;
}
size_t quill_frag_len(const quill_params_t* p, int nb) { return disp_frag_size(quill_D_len(p, nb), p->k); }

/* ----------------------------------------------------------- key schedule */
static void transcript(uint32_t sid, const uint8_t* ct, size_t ctn, const uint8_t* gw_pk, size_t gwn,
                       const uint8_t* dev_pk, size_t devn, uint8_t th[32]) {
    static const uint8_t lab[] = "QUILL-TH";
    uint8_t s[4], hg[32], hd[32]; put32(s, sid);
    h256(gw_pk, gwn, hg); h256(dev_pk, devn, hd);
    const uint8_t* p[5] = { lab, s, ct, hg, hd };
    size_t n[5] = { sizeof lab - 1, 4, ctn, 32, 32 };
    h256v(th, 5, p, n);
}
static void chain_first(const uint8_t ss[32], const uint8_t th[32], uint8_t ck[32]) {
    hkdf(ss, 32, th, 32, (const uint8_t*)"QUILL chain0", 12, ck, 32);
}
static void chain_next(uint8_t ck[32]) {
    uint8_t t[32]; hkdf_expand(ck, (const uint8_t*)"QUILL chain", 11, t, 32);
    memcpy(ck, t, 32); memset(t, 0, 32);
}
static void batch_key(const uint8_t ck[32], uint8_t kb[32]) {
    hkdf_expand(ck, (const uint8_t*)"QUILL batch", 11, kb, 32);
}
static void packet_key(const uint8_t kb[32], int i, uint8_t k[32], uint8_t kc[32]) {
    uint8_t info[10] = { 'Q', 'U', 'I', 'L', 'L', ' ', 'p', 'k', 't', (uint8_t)i };
    hkdf_expand(kb, info, 10, k, 32);
    static const uint8_t lab[] = "QUILL-KC";
    const uint8_t* p[2] = { lab, k }; size_t n[2] = { sizeof lab - 1, 32 };
    h256v(kc, 2, p, n);
}
static void nonce_of(uint32_t b, int i, uint8_t iv[12]) {
    memset(iv, 0, 12); put32(iv, b); iv[4] = (uint8_t)i;
}
/* AUX frames carry fragments of batch b's authenticator under their own keys */
static void aux_key(const uint8_t kb[32], int j, uint8_t k[32]) {
    uint8_t info[10] = { 'Q', 'U', 'I', 'L', 'L', ' ', 'a', 'u', 'x', (uint8_t)j };
    hkdf_expand(kb, info, 10, k, 32);
}
static void aux_nonce(uint32_t b, int j, uint8_t iv[12]) {
    memset(iv, 0, 12); put32(iv, b); iv[4] = (uint8_t)j; iv[11] = 0x01;
}

/* ----------------------------------------------------------- Merkle tree */
void quill_leaf(const uint8_t th[32], uint32_t b, int i, const uint8_t kc[32], const uint8_t* ct, size_t ctlen, uint8_t out[32]) {
    uint8_t pre[6]; pre[0] = 0x00; put32(pre + 1, b); pre[5] = (uint8_t)i;
    const uint8_t* p[4] = { pre, th, kc, ct }; size_t n[4] = { 6, 32, 32, ctlen };
    h256v(out, 4, p, n);
}
static void node(const uint8_t th[32], uint32_t b, const uint8_t* l, const uint8_t* r, uint8_t out[32]) {
    uint8_t pre[5]; pre[0] = 0x01; put32(pre + 1, b);
    const uint8_t* p[4] = { pre, th, l, r }; size_t n[4] = { 5, 32, 32, 32 };
    h256v(out, 4, p, n);
}
static int split(int n) { int k = 1; while (k * 2 < n) k *= 2; return k; }
static void root_rec(const uint8_t th[32], uint32_t b, uint8_t (*leaf)[QUILL_LEAF], int lo, int hi, uint8_t out[32]) {
    if (hi - lo == 1) { memcpy(out, leaf[lo], 32); return; }
    int k = split(hi - lo); uint8_t L[32], R[32];
    root_rec(th, b, leaf, lo, lo + k, L); root_rec(th, b, leaf, lo + k, hi, R);
    node(th, b, L, R, out);
}
void quill_root(const uint8_t th[32], uint32_t b, uint8_t (*leaf)[QUILL_LEAF], int nb, uint8_t out[32]) {
    root_rec(th, b, leaf, 0, nb, out);
}
static void path_rec(const uint8_t th[32], uint32_t b, uint8_t (*leaf)[QUILL_LEAF], int i, int lo, int hi, uint8_t (*path)[32], int* pl) {
    if (hi - lo == 1) return;
    int k = split(hi - lo);
    if (i < lo + k) { path_rec(th, b, leaf, i, lo, lo + k, path, pl); root_rec(th, b, leaf, lo + k, hi, path[(*pl)++]); }
    else            { path_rec(th, b, leaf, i, lo + k, hi, path, pl); root_rec(th, b, leaf, lo, lo + k, path[(*pl)++]); }
}
static void root_from_path(const uint8_t th[32], uint32_t b, int i, int lo, int hi, const uint8_t* lf,
                           const uint8_t (*path)[32], int* pos, uint8_t out[32]) {
    if (hi - lo == 1) { memcpy(out, lf, 32); return; }
    int k = split(hi - lo); uint8_t x[32];
    if (i < lo + k) { root_from_path(th, b, i, lo, lo + k, lf, path, pos, x); node(th, b, x, path[(*pos)++], out); }
    else            { root_from_path(th, b, i, lo + k, hi, lf, path, pos, x); node(th, b, path[(*pos)++], x, out); }
}
size_t quill_batch_msg(const uint8_t th[32], uint32_t b, int nb, const uint8_t root[32], uint8_t* out) {
    static const char lab[] = "QUILL-BATCH";
    size_t o = sizeof lab - 1;
    memcpy(out, lab, o);
    memcpy(out + o, th, 32); o += 32;
    put32(out + o, b); o += 4;
    out[o++] = (uint8_t)nb;
    memcpy(out + o, root, 32); o += 32;
    return o;
}

/* ================================================================== device */
static int dev_need_pt(quill_dev_t* d, size_t n) {
    if (d->ptcap >= n) return 0;
    free(d->pt); d->pt = (uint8_t*)malloc(n); d->ptcap = d->pt ? n : 0;
    return d->pt ? 0 : -1;
}
static int dev_need(quill_dev_t* d, size_t n) {
    if (d->bufcap >= n) return 0;
    free(d->buf); d->buf = (uint8_t*)malloc(n); d->bufcap = d->buf ? n : 0;
    return d->buf ? 0 : -1;
}

int quill_dev_init(quill_dev_t* d, const quill_params_t* p, sig_key_t* sk,
                 const uint8_t* gw_pk, uint32_t sid, quill_emit_fn emit, void* ectx) {
    memset(d, 0, sizeof *d);
    d->p = *p; d->sk = sk; d->sid = sid; d->emit = emit; d->ectx = ectx;
    if (p->n < 1 || p->n > QUILL_MAX_N || p->k < 1 || p->k > p->n || p->m < 0 || p->m + p->n > 255) return -1;
    size_t ctn = kem_ct_len(p->kem), pkn = kem_pk_len(p->kem), devn;
    const uint8_t* dpk = sig_pk(sk, &devn);
    size_t sl = sig_info(p->sig)->sig_len;
    d->Dcap = quill_D_len(p, p->n);
    d->D = (uint8_t*)malloc(d->Dcap);
    d->frag = (uint8_t*)malloc((size_t)p->n * quill_frag_len(p, p->n));
    if (!d->D || !d->frag) return -1;
    if (dev_need(d, 5 + ctn + sl + 64)) return -1;
    uint8_t* f = d->buf; uint8_t ss[32];
    f[0] = 0x00; put32(f + 1, sid);
    if (kem_encaps(p->kem, gw_pk, f + 5, ss)) return -2;
    transcript(sid, f + 5, ctn, gw_pk, pkn, dpk, devn, d->th);
    /* the device authenticates the session by signing the transcript hash */
    uint8_t msg[42]; memcpy(msg, "QUILL-INIT", 10); memcpy(msg + 10, d->th, 32);
    size_t siglen = sl + 64;
    if (sig_sign(sk, msg, 42, f + 5 + ctn, &siglen)) return -3;
    d->signatures++;
    chain_first(ss, d->th, d->ck); memset(ss, 0, 32);
    batch_key(d->ck, d->kb);
    size_t len = 5 + ctn + siglen;
    d->bytes_init += len;
    if (emit) emit(ectx, f, len, 0);
    return 0;
}

/* emit fragment j of the pending authenticator as an AUX frame */
static int dev_aux(quill_dev_t* d, int j) {
    size_t flen = QUILL_HDR_AUX + d->F + QUILL_TAG;
    if (dev_need(d, flen)) return -1;
    uint8_t* f = d->buf; uint8_t k[32], iv[12];
    f[0] = 0x02; put32(f + 1, d->sid); put32(f + 5, d->fb); f[9] = (uint8_t)d->fn; f[10] = (uint8_t)j;
    aux_key(d->kb_prev, j, k); aux_nonce(d->fb, j, iv);
    if (gcm_enc(k, iv, f, QUILL_HDR_AUX, d->frag + (size_t)j * d->F, d->F, f + QUILL_HDR_AUX)) return -2;
    memset(k, 0, 32);
    d->bytes_aux += flen; d->aux_frames++;
    if (d->emit) d->emit(d->ectx, f, flen, 2);
    return 0;
}
static int dev_flush_pending(quill_dev_t* d) {
    if (!d->fn) return 0;
    for (int j = d->fsent; j < d->p.n; ++j) if (dev_aux(d, j)) return -1;
    d->fn = 0; d->fsent = 0;
    return 0;
}

/* close the current batch: sign its root and disperse D */
static int dev_close_batch(quill_dev_t* d, int send_now) {
    int nb = d->i;
    if (nb == 0) return 0;
    if (dev_flush_pending(d)) return -1;          /* previous D must be out first */
    uint8_t root[32], msg[96];
    quill_root(d->th, d->b, d->leaf, nb, root);
    size_t ml = quill_batch_msg(d->th, d->b, nb, root, msg);
    size_t sl = sig_info(d->p.sig)->sig_len, siglen = sl;
    if (sig_sign(d->sk, msg, ml, d->D, &siglen)) return -2;
    if (siglen < sl) memset(d->D + siglen, 0, sl - siglen);
    d->signatures++;
    int me = quill_m_eff(&d->p, nb);
    const uint8_t* lp[QUILL_MAX_N]; uint8_t* pp[QUILL_MAX_N];
    for (int j = 0; j < nb; ++j) lp[j] = d->leaf[j];
    for (int r = 0; r < me; ++r) pp[r] = d->D + sl + (size_t)r * QUILL_LEAF;
    ecc_parity(lp, nb, pp, me, QUILL_LEAF);
    size_t Dn = quill_D_len(&d->p, nb);
    d->F = disp_frag_size(Dn, d->p.k);
    disp_encode(d->D, Dn, d->p.k, d->p.n, d->frag);
    d->fn = nb; d->fb = d->b; d->fsent = 0;
    memcpy(d->kb_prev, d->kb, 32);
    /* next batch */
    d->b++; d->i = 0;
    chain_next(d->ck); batch_key(d->ck, d->kb);
    if (send_now) return dev_flush_pending(d);
    return 0;
}

int quill_dev_send(quill_dev_t* d, const uint8_t* payload, size_t len, int urgent) {
    const int i = d->i;
    int carry = d->fn && d->fsent < d->p.n;
    size_t F = carry ? d->F : 0;
    size_t flen = QUILL_HDR_DATA + F + len + QUILL_TAG;
    if (dev_need(d, flen)) return -1;
    uint8_t* f = d->buf;
    f[0] = 0x01; put32(f + 1, d->sid); put32(f + 5, d->b); f[9] = (uint8_t)i;
    f[10] = carry ? (uint8_t)d->fn : 0; f[11] = carry ? (uint8_t)d->fsent : 0;
    /* plaintext = fragment of the previous batch's authenticator || payload */
    if (dev_need_pt(d, F + len)) return -1;
    if (carry) { memcpy(d->pt, d->frag + (size_t)d->fsent * d->F, F); d->fsent++; if (d->fsent == d->p.n) d->fn = 0, d->fsent = 0; }
    memcpy(d->pt + F, payload, len);
    uint8_t k[32], kc[32], iv[12];
    packet_key(d->kb, i, k, kc);
    nonce_of(d->b, i, iv);
    uint8_t* ct = f + QUILL_HDR_DATA;
    if (gcm_enc(k, iv, f, QUILL_HDR_DATA, d->pt, F + len, ct)) return -2;
    memset(k, 0, 32);
    quill_leaf(d->th, d->b, i, kc, ct, F + len + QUILL_TAG, d->leaf[i]);
    d->i++;
    d->packets++; d->payload_bytes += len; d->bytes_data += flen;
    if (d->emit) d->emit(d->ectx, f, flen, 1);
    if (urgent) return dev_close_batch(d, d->p.urgent_aux);
    if (d->i == d->p.n) return dev_close_batch(d, 0);
    return 0;
}

int quill_dev_close(quill_dev_t* d) {
    if (dev_close_batch(d, 1)) return -1;
    return dev_flush_pending(d);
}
void quill_dev_free(quill_dev_t* d) { free(d->D); free(d->frag); free(d->buf); free(d->pt); memset(d, 0, sizeof *d); }

/* ================================================================= gateway */
int quill_gw_init(quill_gw_t* g, const quill_params_t* p, kem_gw_t* kem, const uint8_t* dev_pk, size_t dev_pklen) {
    memset(g, 0, sizeof *g);
    g->p = *p; g->kem = kem; g->dev_pk = dev_pk; g->dev_pklen = dev_pklen;
    return 0;
}
static void gw_chain_to(quill_gw_t* g, uint32_t b, uint8_t ck[32]) {
    if (b < g->ck_b) { memcpy(g->ck, g->ck0, 32); g->ck_b = 0; }
    while (g->ck_b < b) { chain_next(g->ck); g->ck_b++; }
    memcpy(ck, g->ck, 32);
}
int quill_gw_packet_key(quill_gw_t* g, uint32_t b, int i, uint8_t key[32]) {
    uint8_t ck[32], kb[32], kc[32];
    gw_chain_to(g, b, ck); batch_key(ck, kb); packet_key(kb, i, key, kc);
    return 0;
}
static quill_gw_batch_t* gw_batch(quill_gw_t* g, uint32_t b, int create);
static void gw_settle(quill_gw_t* g, quill_gw_batch_t* B, int final);

static void gw_release(quill_gw_t* g, quill_gw_batch_t* B) {
    if (B->used && B->state == 0) gw_settle(g, B, 1);
    free(B->frag); free(B->sig);
    memset(B, 0, sizeof *B);
}
static quill_gw_batch_t* gw_batch(quill_gw_t* g, uint32_t b, int create) {
    quill_gw_batch_t* B = &g->ring[b % QUILL_RING];
    if (B->used && B->b == b) return B;
    if (!create) return NULL;
    if (B->used) { if (B->b > b) return NULL; gw_release(g, B); }
    B->used = 1; B->b = b;
    return B;
}

/* try to rebuild D and verify; final = no more fragments will come */
static void gw_settle(quill_gw_t* g, quill_gw_batch_t* B, int final) {
    if (B->state != 0) return;
    if (!B->nb || B->nfr < g->p.k) { if (final) goto fail; return; }
    {
        int nb = B->nb, me = quill_m_eff(&g->p, nb);
        size_t Dn = quill_D_len(&g->p, nb), sl = sig_info(g->p.sig)->sig_len;
        uint8_t* D = (uint8_t*)malloc(Dn);
        if (!D || disp_decode(B->frag, B->fhave, g->p.k, g->p.n, Dn, D)) { free(D); goto fail; }
        int miss[QUILL_MAX_N], ne = 0;
        for (int i = 0; i < nb; ++i) if (!B->have[i]) miss[ne++] = i;
        if (ne > me) { free(D); goto fail; }
        uint8_t* lp[QUILL_MAX_N]; const uint8_t* pp[QUILL_MAX_N]; int prow[QUILL_MAX_N];
        for (int i = 0; i < nb; ++i) lp[i] = B->leaf[i];
        for (int r = 0; r < ne; ++r) { pp[r] = D + sl + (size_t)r * QUILL_LEAF; prow[r] = r; }
        if (ecc_recover(lp, nb, miss, ne, pp, prow, me, QUILL_LEAF)) { free(D); goto fail; }
        uint8_t msg[96];
        quill_root(g->th, B->b, B->leaf, nb, B->root);
        size_t ml = quill_batch_msg(g->th, B->b, nb, B->root, msg);
        if (sig_verify(g->p.sig, g->dev_pk, g->dev_pklen, msg, ml, D, sl)) { free(D); goto fail; }
        B->sig = (uint8_t*)malloc(sl); if (B->sig) { memcpy(B->sig, D, sl); B->siglen = sl; }
        free(D);
        B->state = 1; g->batches_ok++;
        for (int i = 0; i < nb; ++i) if (B->have[i]) g->nr_packets++;
        if (g->on_batch) g->on_batch(g->cctx, B->b, nb, 1, B->have);
        return;
    }
fail:
    B->state = -1; g->batches_fail++;
    if (g->on_batch) g->on_batch(g->cctx, B->b, B->nb, 0, B->have);
}

static void gw_add_frag(quill_gw_t* g, uint32_t b, int fn, int fj, const uint8_t* fr) {
    quill_gw_batch_t* B = gw_batch(g, b, 1);
    if (!B || B->state != 0 || fn < 1 || fn > g->p.n || fj >= g->p.n) return;
    if (!B->nb) {
        B->nb = fn; B->F = quill_frag_len(&g->p, fn);
        B->frag = (uint8_t*)malloc((size_t)g->p.n * B->F);
    }
    if (fn != B->nb || !B->frag || B->fhave[fj]) return;
    memcpy(B->frag + (size_t)fj * B->F, fr, B->F);
    B->fhave[fj] = 1; B->nfr++;
    if (B->nfr >= g->p.k) gw_settle(g, B, 0);
}

int quill_gw_recv(quill_gw_t* g, const uint8_t* f, size_t len) {
    if (len < 5) return -1;
    uint32_t sid = get32(f + 1);
    if (f[0] == 0x00) {
        size_t ctn = kem_ct_len(g->p.kem), pkn = kem_pk_len(g->p.kem), sl = len - 5 - ctn;
        if (len < 5 + ctn) return -1;
        uint8_t ss[32], msg[42];
        if (kem_decaps(g->kem, f + 5, ss)) return -2;
        transcript(sid, f + 5, ctn, kem_gw_pk(g->kem), pkn, g->dev_pk, g->dev_pklen, g->th);
        memcpy(msg, "QUILL-INIT", 10); memcpy(msg + 10, g->th, 32);
        if (sig_verify(g->p.sig, g->dev_pk, g->dev_pklen, msg, 42, f + 5 + ctn, sl)) return -3;
        chain_first(ss, g->th, g->ck0); memset(ss, 0, 32);
        memcpy(g->ck, g->ck0, 32); g->ck_b = 0;
        g->sid = sid; g->ready = 1;
        return 0;
    }
    if (!g->ready || sid != g->sid) return -4;
    if (f[0] == 0x02) {
        if (len < QUILL_HDR_AUX) return -1;
        uint32_t b = get32(f + 5); int fn = f[9], fj = f[10];
        size_t F = fn >= 1 && fn <= g->p.n ? quill_frag_len(&g->p, fn) : 0;
        if (!F || fj >= g->p.n || len != QUILL_HDR_AUX + F + QUILL_TAG) return -1;
        uint8_t ck[32], kb[32], k[32], iv[12];
        uint8_t* fr = (uint8_t*)malloc(F);
        if (!fr) return -1;
        gw_chain_to(g, b, ck); batch_key(ck, kb); aux_key(kb, fj, k); aux_nonce(b, fj, iv);
        if (gcm_dec(k, iv, f, QUILL_HDR_AUX, f + QUILL_HDR_AUX, F + QUILL_TAG, fr)) { free(fr); g->rx_auth_fail++; return -5; }
        gw_add_frag(g, b, fn, fj, fr);
        free(fr);
        return 0;
    }
    if (f[0] != 0x01 || len < QUILL_HDR_DATA + QUILL_TAG) return -1;
    uint32_t b = get32(f + 5); int i = f[9], fn = f[10], fj = f[11];
    size_t F = fn ? quill_frag_len(&g->p, fn) : 0;
    if (i >= g->p.n || (fn && fj >= g->p.n) || len < QUILL_HDR_DATA + F + QUILL_TAG) return -1;
    const uint8_t* ct = f + QUILL_HDR_DATA; size_t ctn = len - QUILL_HDR_DATA;
    /* 1) immediate symmetric authenticity */
    uint8_t ck[32], kb[32], k[32], kc[32], iv[12];
    gw_chain_to(g, b, ck); batch_key(ck, kb); packet_key(kb, i, k, kc); nonce_of(b, i, iv);
    uint8_t* pt = (uint8_t*)malloc(ctn);
    if (!pt) return -1;
    if (gcm_dec(k, iv, f, QUILL_HDR_DATA, ct, ctn, pt)) { free(pt); g->rx_auth_fail++; return -5; }
    g->rx_data++;
    if (g->on_data) g->on_data(g->cctx, b, i, pt + F, ctn - QUILL_TAG - F);
    /* 2) record the leaf for non-repudiation */
    quill_gw_batch_t* B = gw_batch(g, b, 1);
    if (B && B->state == 0 && !B->have[i]) {
        quill_leaf(g->th, b, i, kc, ct, ctn, B->leaf[i]);
        memcpy(B->kc[i], kc, 32);
        B->have[i] = 1;
    }
    /* 3) the (authenticated) fragment belongs to the previous batch */
    if (fn && b > 0) gw_add_frag(g, b - 1, fn, fj, pt);
    free(pt);
    return 0;
}

void quill_gw_finish(quill_gw_t* g) {
    for (int r = 0; r < QUILL_RING; ++r) if (g->ring[r].used && g->ring[r].state == 0) gw_settle(g, &g->ring[r], 1);
}
void quill_gw_free(quill_gw_t* g) {
    for (int r = 0; r < QUILL_RING; ++r) { free(g->ring[r].frag); free(g->ring[r].sig); }
    memset(g, 0, sizeof *g);
}

/* ================================================================ evidence */
int quill_gw_evidence(quill_gw_t* g, uint32_t b, int i, const uint8_t* hdr, const uint8_t* ct, size_t ctlen, quill_evidence_t* ev) {
    quill_gw_batch_t* B = gw_batch(g, b, 0);
    if (!B || B->state != 1 || i >= B->nb || !B->have[i]) return -1;
    memset(ev, 0, sizeof *ev);
    memcpy(ev->th, g->th, 32); ev->b = b; ev->nb = B->nb; ev->i = i;
    memcpy(ev->hdr, hdr, QUILL_HDR_DATA);
    memcpy(ev->kc, B->kc[i], 32);
    ev->ct = ct; ev->ctlen = ctlen;
    path_rec(g->th, b, B->leaf, i, 0, B->nb, ev->path, &ev->plen);
    ev->sig = B->sig; ev->siglen = B->siglen;
    return 0;
}
int quill_audit(int sig, const uint8_t* dev_pk, size_t pklen, const quill_evidence_t* ev) {
    uint8_t lf[32], root[32], msg[96]; int pos = 0;
    quill_leaf(ev->th, ev->b, ev->i, ev->kc, ev->ct, ev->ctlen, lf);
    root_from_path(ev->th, ev->b, ev->i, 0, ev->nb, lf, (const uint8_t (*)[32])ev->path, &pos, root);
    if (pos != ev->plen) return -1;
    size_t ml = quill_batch_msg(ev->th, ev->b, ev->nb, root, msg);
    return sig_verify(sig, dev_pk, pklen, msg, ml, ev->sig, ev->siglen) ? -1 : 0;
}
int quill_audit_open(const quill_evidence_t* ev, const uint8_t key[32], uint8_t* pt) {
    static const uint8_t lab[] = "QUILL-KC";
    uint8_t kc[32], iv[12];
    const uint8_t* p[2] = { lab, key }; size_t n[2] = { sizeof lab - 1, 32 };
    h256v(kc, 2, p, n);
    if (memcmp(kc, ev->kc, 32)) return -1;               /* key commitment */
    if (ev->hdr[0] != 0x01 || get32(ev->hdr + 5) != ev->b || ev->hdr[9] != (uint8_t)ev->i) return -1;
    nonce_of(ev->b, ev->i, iv);
    return gcm_dec(key, iv, ev->hdr, QUILL_HDR_DATA, ev->ct, ev->ctlen, pt) ? -1 : 0;
}
