/* Thin wrappers over wolfCrypt and PQClean used by the protocol.
   The same code is compiled for the host (gateway, verifier, simulations)
   and for the Cortex-M4 firmware (device). */
#ifndef QUILL_CRYPTO_H
#define QUILL_CRYPTO_H
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int  crypto_init(void);
void rng_bytes(uint8_t* out, size_t n);

void h256(const uint8_t* d, size_t n, uint8_t out[32]);
/* SHA-256 over the concatenation of up to 6 pieces */
void h256v(uint8_t out[32], int cnt, const uint8_t* const* p, const size_t* n);
int  hkdf(const uint8_t* ikm, size_t ikmn, const uint8_t* salt, size_t saltn,
          const uint8_t* info, size_t infon, uint8_t* out, size_t outn);
/* HKDF-Expand only, for keys that are already uniform */
int  hkdf_expand(const uint8_t prk[32], const uint8_t* info, size_t infon, uint8_t* out, size_t outn);
/* AES-256-GCM, 12-byte nonce, 16-byte tag appended to out */
int  gcm_enc(const uint8_t key[32], const uint8_t iv[12], const uint8_t* aad, size_t aadn,
             const uint8_t* m, size_t n, uint8_t* out);
int  gcm_dec(const uint8_t key[32], const uint8_t iv[12], const uint8_t* aad, size_t aadn,
             const uint8_t* c, size_t n /* incl. tag */, uint8_t* out);

/* ---------------------------------------------------------------- signatures */
enum sig_id {
    SIG_MLDSA44 = 0,   /* ML-DSA-44, FIPS 204 (wolfCrypt)                       */
    SIG_FALCON512,     /* Falcon-512, padded encoding (PQClean)                 */
    SIG_SPHINCS128S,   /* SPHINCS+-SHA2-128s-simple (PQClean)                   */
    SIG_SPHINCS128F,   /* SPHINCS+-SHA2-128f-simple (PQClean)                   */
    SIG_LMS,           /* HSS/LMS, SHA-256/M32, L=2 H=10 W=4 (wolfCrypt)        */
    SIG_ED25519,       /* classical reference (wolfCrypt)                       */
    SIG_MLDSA44_REF,   /* ML-DSA-44 PQClean, cross-check of the wolfCrypt build */
    SIG_COUNT
};
typedef struct {
    const char* name;
    size_t pk_len, sig_len;
    int stateful, post_quantum;
} sig_info_t;
const sig_info_t* sig_info(int id);

typedef struct sig_key sig_key_t;     /* opaque, one signer or verifier key */
sig_key_t* sig_keygen(int id);        /* returns NULL on failure */
const uint8_t* sig_pk(const sig_key_t* k, size_t* len);
int  sig_sign(sig_key_t* k, const uint8_t* m, size_t n, uint8_t* sig, size_t* siglen);
int  sig_verify(int id, const uint8_t* pk, size_t pkn, const uint8_t* m, size_t n,
                const uint8_t* sig, size_t siglen);   /* 0 = valid */
int  sig_set_lms_params(int levels, int height, int winternitz);  /* before keygen */

/* --------------------------------------------------------------- hybrid KEM */
/* X25519 + ML-KEM (512 or 768). Combined secret:
   ss = SHA-256("QUILL-HYB" || ss_mlkem || ss_x25519 || ct_mlkem || epk || pk_x25519) */
enum { KEM_MLKEM512 = 0, KEM_MLKEM768 = 1 };
#define KEM_MAX_PK  (1184 + 32)
#define KEM_MAX_CT  (1088 + 32)
typedef struct kem_gw kem_gw_t;
size_t kem_pk_len(int level);
size_t kem_ct_len(int level);
kem_gw_t* kem_gw_keygen(int level);
const uint8_t* kem_gw_pk(const kem_gw_t* g);
/* device side: encapsulate to the gateway public key */
int  kem_encaps(int level, const uint8_t* pk, uint8_t* ct, uint8_t ss[32]);
int  kem_decaps(kem_gw_t* g, const uint8_t* ct, uint8_t ss[32]);

#ifdef __cplusplus
}
#endif
#endif
