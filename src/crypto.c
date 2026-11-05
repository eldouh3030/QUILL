#include "crypto.h"
#include <string.h>
#include <stdlib.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/kyber.h>
#include <wolfssl/wolfcrypt/wc_kyber.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/lms.h>
#include <wolfssl/wolfcrypt/wc_lms.h>

/* PQClean entry points */
#define PQ_DECL(NS) \
    int NS##_crypto_sign_keypair(uint8_t* pk, uint8_t* sk); \
    int NS##_crypto_sign_signature(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* sk); \
    int NS##_crypto_sign_verify(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk);
PQ_DECL(PQCLEAN_FALCONPADDED512_CLEAN)
PQ_DECL(PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN)
PQ_DECL(PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN)
PQ_DECL(PQCLEAN_MLDSA44_CLEAN)

static WC_RNG g_rng;
static int g_init = 0;

int crypto_init(void) {
    if (g_init) return 0;
    if (wc_InitRng(&g_rng) != 0) return -1;
    g_init = 1;
    return 0;
}
void rng_bytes(uint8_t* out, size_t n) { wc_RNG_GenerateBlock(&g_rng, out, (word32)n); }
/* PQClean randomness source */
int PQCLEAN_randombytes(uint8_t* out, size_t n) { rng_bytes(out, n); return 0; }

void h256(const uint8_t* d, size_t n, uint8_t out[32]) { wc_Sha256Hash(d, (word32)n, out); }
void h256v(uint8_t out[32], int cnt, const uint8_t* const* p, const size_t* n) {
    wc_Sha256 s; wc_InitSha256(&s);
    for (int i = 0; i < cnt; ++i) if (n[i]) wc_Sha256Update(&s, p[i], (word32)n[i]);
    wc_Sha256Final(&s, out); wc_Sha256Free(&s);
}
int hkdf(const uint8_t* ikm, size_t ikmn, const uint8_t* salt, size_t saltn,
         const uint8_t* info, size_t infon, uint8_t* out, size_t outn) {
    return wc_HKDF(WC_SHA256, ikm, (word32)ikmn, salt, (word32)saltn, info, (word32)infon, out, (word32)outn);
}
int hkdf_expand(const uint8_t prk[32], const uint8_t* info, size_t infon, uint8_t* out, size_t outn) {
    return wc_HKDF_Expand(WC_SHA256, prk, 32, info, (word32)infon, out, (word32)outn);
}
int gcm_enc(const uint8_t key[32], const uint8_t iv[12], const uint8_t* aad, size_t aadn,
            const uint8_t* m, size_t n, uint8_t* out) {
    Aes aes; int r;
    if ((r = wc_AesInit(&aes, NULL, INVALID_DEVID)) != 0) return r;
    if ((r = wc_AesGcmSetKey(&aes, key, 32)) == 0)
        r = wc_AesGcmEncrypt(&aes, out, m, (word32)n, iv, 12, out + n, 16, aad, (word32)aadn);
    wc_AesFree(&aes);
    return r;
}
int gcm_dec(const uint8_t key[32], const uint8_t iv[12], const uint8_t* aad, size_t aadn,
            const uint8_t* c, size_t n, uint8_t* out) {
    Aes aes; int r;
    if (n < 16) return -1;
    if ((r = wc_AesInit(&aes, NULL, INVALID_DEVID)) != 0) return r;
    if ((r = wc_AesGcmSetKey(&aes, key, 32)) == 0)
        r = wc_AesGcmDecrypt(&aes, out, c, (word32)(n - 16), iv, 12, c + n - 16, 16, aad, (word32)aadn);
    wc_AesFree(&aes);
    return r;
}

/* ---------------------------------------------------------------- signatures */
static const sig_info_t INFO[SIG_COUNT] = {
    { "ML-DSA-44",            1312, 2420,  0, 1 },
    { "Falcon-512",            897,  666,  0, 1 },
    { "SPHINCS+-SHA2-128s",     32, 7856,  0, 1 },
    { "SPHINCS+-SHA2-128f",     32, 17088, 0, 1 },
    { "LMS (HSS L2 H10 W4)",    60, 0,     1, 1 },   /* sig_len set at keygen */
    { "Ed25519",                32,   64,  0, 0 },
    { "ML-DSA-44 (PQClean)",  1312, 2420,  0, 1 },
};
static sig_info_t g_info[SIG_COUNT];
static int g_info_init = 0;
static int lms_levels = 2, lms_height = 10, lms_w = 4;

const sig_info_t* sig_info(int id) {
    if (!g_info_init) { memcpy(g_info, INFO, sizeof INFO); g_info_init = 1; }
    if (id < 0 || id >= SIG_COUNT) return NULL;
    if (id == SIG_LMS && g_info[id].sig_len == 0) {
        /* signature length of HSS: 4 + (L-1)*(lms_sig + 60) + lms_sig, lms_sig = 4+ (4+32+p*32) + 4 + 32*H */
        int p = lms_w == 1 ? 265 : lms_w == 2 ? 133 : lms_w == 4 ? 67 : 34;
        size_t ls = 4 + (4 + 32 + (size_t)p * 32) + 4 + 32 * (size_t)lms_height;
        g_info[id].sig_len = 4 + (size_t)(lms_levels - 1) * (ls + 56) + ls;
    }
    return &g_info[id];
}
int sig_set_lms_params(int levels, int height, int winternitz) {
    lms_levels = levels; lms_height = height; lms_w = winternitz;
    sig_info(0); g_info[SIG_LMS].sig_len = 0;
    static char nm[48]; char* q = nm;
    const char* a = "LMS (HSS L"; while (*a) *q++ = *a++;
    *q++ = (char)('0' + levels); *q++ = ' '; *q++ = 'H';
    if (height >= 10) *q++ = (char)('0' + height / 10);
    *q++ = (char)('0' + height % 10); *q++ = ' '; *q++ = 'W'; *q++ = (char)('0' + winternitz); *q++ = ')'; *q = 0;
    g_info[SIG_LMS].name = nm;
    return 0;
}

struct sig_key {
    int id;
    uint8_t pk[1312]; size_t pklen;
    uint8_t* sk;                     /* PQClean secret key */
    dilithium_key* dk;
    ed25519_key* ek;
    LmsKey* lk;
    uint8_t* lms_priv; word32 lms_priv_len;   /* "non-volatile" state of the LMS key */
};

static int lms_write(const byte* priv, word32 sz, void* ctx) {
    sig_key_t* k = (sig_key_t*)ctx;
    if (!k->lms_priv) { k->lms_priv = (uint8_t*)malloc(sz); k->lms_priv_len = sz; }
    if (!k->lms_priv || sz > k->lms_priv_len) return WC_LMS_RC_WRITE_FAIL;
    memcpy(k->lms_priv, priv, sz);
    return WC_LMS_RC_SAVED_TO_NV_MEMORY;
}
static int lms_read(byte* priv, word32 sz, void* ctx) {
    sig_key_t* k = (sig_key_t*)ctx;
    if (!k->lms_priv || sz > k->lms_priv_len) return WC_LMS_RC_READ_FAIL;
    memcpy(priv, k->lms_priv, sz);
    return WC_LMS_RC_READ_TO_MEMORY;
}

sig_key_t* sig_keygen(int id) {
    sig_key_t* k = (sig_key_t*)calloc(1, sizeof *k);
    if (!k) return NULL;
    k->id = id; int r = 0;
    switch (id) {
    case SIG_MLDSA44: {
        k->dk = (dilithium_key*)calloc(1, sizeof(dilithium_key));
        word32 l = sizeof k->pk;
        r = wc_dilithium_init(k->dk);
        if (!r) r = wc_dilithium_set_level(k->dk, WC_ML_DSA_44);
        if (!r) r = wc_dilithium_make_key(k->dk, &g_rng);
        if (!r) r = wc_dilithium_export_public(k->dk, k->pk, &l);
        k->pklen = l; break; }
    case SIG_ED25519: {
        k->ek = (ed25519_key*)calloc(1, sizeof(ed25519_key));
        word32 l = 32;
        r = wc_ed25519_init(k->ek);
        if (!r) r = wc_ed25519_make_key(&g_rng, 32, k->ek);
        if (!r) r = wc_ed25519_export_public(k->ek, k->pk, &l);
        k->pklen = l; break; }
    case SIG_LMS: {
        k->lk = (LmsKey*)calloc(1, sizeof(LmsKey));
        word32 l = sizeof k->pk;
        r = wc_LmsKey_Init(k->lk, NULL, INVALID_DEVID);
        if (!r) r = wc_LmsKey_SetParameters(k->lk, lms_levels, lms_height, lms_w);
        if (!r) r = wc_LmsKey_SetWriteCb(k->lk, lms_write);
        if (!r) r = wc_LmsKey_SetReadCb(k->lk, lms_read);
        if (!r) r = wc_LmsKey_SetContext(k->lk, k);
        if (!r) r = wc_LmsKey_MakeKey(k->lk, &g_rng);
        if (!r) r = wc_LmsKey_ExportPubRaw(k->lk, k->pk, &l);
        if (!r) { word32 sl; if (wc_LmsKey_GetSigLen(k->lk, &sl) == 0) { sig_info(0); g_info[SIG_LMS].sig_len = sl; g_info[SIG_LMS].pk_len = l; } }
        k->pklen = l; break; }
#define PQC_KG(ID, NS, SKLEN) case ID: k->sk = (uint8_t*)malloc(SKLEN); \
        r = NS##_crypto_sign_keypair(k->pk, k->sk); k->pklen = INFO[ID].pk_len; break;
    PQC_KG(SIG_FALCON512, PQCLEAN_FALCONPADDED512_CLEAN, 1281)
    PQC_KG(SIG_SPHINCS128S, PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN, 64)
    PQC_KG(SIG_SPHINCS128F, PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN, 64)
    PQC_KG(SIG_MLDSA44_REF, PQCLEAN_MLDSA44_CLEAN, 2560)
    default: r = -1;
    }
    if (r) { free(k); return NULL; }
    return k;
}
const uint8_t* sig_pk(const sig_key_t* k, size_t* len) { *len = k->pklen; return k->pk; }

int sig_sign(sig_key_t* k, const uint8_t* m, size_t n, uint8_t* sig, size_t* siglen) {
    switch (k->id) {
    case SIG_MLDSA44: { word32 l = (word32)*siglen;
        int r = wc_dilithium_sign_msg(m, (word32)n, sig, &l, k->dk, &g_rng); *siglen = l; return r; }
    case SIG_ED25519: { word32 l = (word32)*siglen;
        int r = wc_ed25519_sign_msg(m, (word32)n, sig, &l, k->ek); *siglen = l; return r; }
    case SIG_LMS: { word32 l = (word32)*siglen;
        int r = wc_LmsKey_Sign(k->lk, sig, &l, m, (int)n); *siglen = l; return r; }
    case SIG_FALCON512:   return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(sig, siglen, m, n, k->sk);
    case SIG_SPHINCS128S: return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, n, k->sk);
    case SIG_SPHINCS128F: return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, n, k->sk);
    case SIG_MLDSA44_REF: return PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, siglen, m, n, k->sk);
    }
    return -1;
}

int sig_verify(int id, const uint8_t* pk, size_t pkn, const uint8_t* m, size_t n,
               const uint8_t* sig, size_t siglen) {
    switch (id) {
    case SIG_MLDSA44: {
        dilithium_key key; int res = 0, r;
        wc_dilithium_init(&key); wc_dilithium_set_level(&key, WC_ML_DSA_44);
        r = wc_dilithium_import_public(pk, (word32)pkn, &key);
        if (!r) r = wc_dilithium_verify_msg(sig, (word32)siglen, m, (word32)n, &res, &key);
        wc_dilithium_free(&key);
        return (!r && res == 1) ? 0 : -1; }
    case SIG_ED25519: {
        ed25519_key key; int res = 0, r;
        wc_ed25519_init(&key);
        r = wc_ed25519_import_public(pk, (word32)pkn, &key);
        if (!r) r = wc_ed25519_verify_msg(sig, (word32)siglen, m, (word32)n, &res, &key);
        wc_ed25519_free(&key);
        return (!r && res == 1) ? 0 : -1; }
    case SIG_LMS: {
        LmsKey key; int r;
        wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
        r = wc_LmsKey_SetParameters(&key, lms_levels, lms_height, lms_w);
        if (!r) r = wc_LmsKey_ImportPubRaw(&key, pk, (word32)pkn);
        if (!r) r = wc_LmsKey_Verify(&key, sig, (word32)siglen, m, (int)n);
        wc_LmsKey_Free(&key);
        return r ? -1 : 0; }
    case SIG_FALCON512:   return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(sig, siglen, m, n, pk) ? -1 : 0;
    case SIG_SPHINCS128S: return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, n, pk) ? -1 : 0;
    case SIG_SPHINCS128F: return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, n, pk) ? -1 : 0;
    case SIG_MLDSA44_REF: return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, m, n, pk) ? -1 : 0;
    }
    return -1;
}

/* --------------------------------------------------------------- hybrid KEM */
struct kem_gw {
    int level;
    KyberKey kk;
    curve25519_key xk;
    uint8_t pk[KEM_MAX_PK];
};
static int kem_type(int level) { return level == KEM_MLKEM768 ? WC_ML_KEM_768 : WC_ML_KEM_512; }
static size_t mlkem_pk_len(int level) { return level == KEM_MLKEM768 ? 1184 : 800; }
static size_t mlkem_ct_len(int level) { return level == KEM_MLKEM768 ? 1088 : 768; }
size_t kem_pk_len(int level) { return mlkem_pk_len(level) + 32; }
size_t kem_ct_len(int level) { return mlkem_ct_len(level) + 32; }

static void combine(int level, const uint8_t* ss_k, const uint8_t* ss_x, const uint8_t* ct, const uint8_t* pk, uint8_t out[32]) {
    static const uint8_t label[] = "QUILL-HYB";
    const uint8_t* p[6] = { label, ss_k, ss_x, ct, ct + mlkem_ct_len(level), pk + mlkem_pk_len(level) };
    size_t n[6] = { sizeof label - 1, 32, 32, mlkem_ct_len(level), 32, 32 };
    h256v(out, 6, p, n);
}

kem_gw_t* kem_gw_keygen(int level) {
    kem_gw_t* g = (kem_gw_t*)calloc(1, sizeof *g);
    if (!g) return NULL;
    g->level = level; int r; word32 l = 32;
    r = wc_KyberKey_Init(kem_type(level), &g->kk, NULL, INVALID_DEVID);
    if (!r) r = wc_KyberKey_MakeKey(&g->kk, &g_rng);
    if (!r) r = wc_KyberKey_EncodePublicKey(&g->kk, g->pk, (word32)mlkem_pk_len(level));
    if (!r) r = wc_curve25519_init(&g->xk);
    if (!r) r = wc_curve25519_make_key(&g_rng, 32, &g->xk);
    if (!r) r = wc_curve25519_export_public_ex(&g->xk, g->pk + mlkem_pk_len(level), &l, EC25519_LITTLE_ENDIAN);
    if (r) { free(g); return NULL; }
    return g;
}
const uint8_t* kem_gw_pk(const kem_gw_t* g) { return g->pk; }

int kem_encaps(int level, const uint8_t* pk, uint8_t* ct, uint8_t ss[32]) {
    KyberKey kk; curve25519_key e, peer; uint8_t ss_k[32], ss_x[32]; int r; word32 l;
    r = wc_KyberKey_Init(kem_type(level), &kk, NULL, INVALID_DEVID);
    if (!r) r = wc_KyberKey_DecodePublicKey(&kk, pk, (word32)mlkem_pk_len(level));
    if (!r) r = wc_KyberKey_Encapsulate(&kk, ct, ss_k, &g_rng);
    wc_KyberKey_Free(&kk);
    if (r) return r;
    wc_curve25519_init(&e); wc_curve25519_init(&peer);
    r = wc_curve25519_make_key(&g_rng, 32, &e);
    l = 32;
    if (!r) r = wc_curve25519_export_public_ex(&e, ct + mlkem_ct_len(level), &l, EC25519_LITTLE_ENDIAN);
    if (!r) r = wc_curve25519_import_public_ex(pk + mlkem_pk_len(level), 32, &peer, EC25519_LITTLE_ENDIAN);
    l = 32;
    if (!r) r = wc_curve25519_shared_secret_ex(&e, &peer, ss_x, &l, EC25519_LITTLE_ENDIAN);
    wc_curve25519_free(&e); wc_curve25519_free(&peer);
    if (r) return r;
    combine(level, ss_k, ss_x, ct, pk, ss);
    memset(ss_k, 0, 32); memset(ss_x, 0, 32);
    return 0;
}

int kem_decaps(kem_gw_t* g, const uint8_t* ct, uint8_t ss[32]) {
    curve25519_key peer; uint8_t ss_k[32], ss_x[32]; int r; word32 l = 32;
    r = wc_KyberKey_Decapsulate(&g->kk, ss_k, ct, (word32)mlkem_ct_len(g->level));
    if (r) return r;
    wc_curve25519_init(&peer);
    r = wc_curve25519_import_public_ex(ct + mlkem_ct_len(g->level), 32, &peer, EC25519_LITTLE_ENDIAN);
    if (!r) r = wc_curve25519_shared_secret_ex(&g->xk, &peer, ss_x, &l, EC25519_LITTLE_ENDIAN);
    wc_curve25519_free(&peer);
    if (r) return r;
    combine(g->level, ss_k, ss_x, ct, g->pk, ss);
    memset(ss_k, 0, 32); memset(ss_x, 0, 32);
    return 0;
}
