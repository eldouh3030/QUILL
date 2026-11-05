#include "ecc.h"
#include <string.h>
#include <stdlib.h>

static uint8_t EXP[512], LOG[256];
static int gf_ready = 0;

void gf_init(void) {
    if (gf_ready) return;
    unsigned x = 1;
    for (int i = 0; i < 255; ++i) {
        EXP[i] = (uint8_t)x; LOG[x] = (uint8_t)i;
        x <<= 1; if (x & 0x100) x ^= 0x11d;
    }
    for (int i = 255; i < 512; ++i) EXP[i] = EXP[i - 255];
    gf_ready = 1;
}
static inline uint8_t gmul(uint8_t a, uint8_t b) { return (a && b) ? EXP[LOG[a] + LOG[b]] : 0; }
static inline uint8_t ginv(uint8_t a) { return EXP[255 - LOG[a]]; }
static inline uint8_t cauchy(int x, int y) { return ginv((uint8_t)(x ^ y)); }

/* dst ^= c * src */
static void axpy(uint8_t* dst, const uint8_t* src, uint8_t c, size_t len) {
    if (!c) return;
    if (c == 1) { for (size_t i = 0; i < len; ++i) dst[i] ^= src[i]; return; }
    unsigned lc = LOG[c];
    for (size_t i = 0; i < len; ++i) { uint8_t s = src[i]; if (s) dst[i] ^= EXP[lc + LOG[s]]; }
}
static void scale(uint8_t* v, uint8_t c, size_t len) {
    unsigned lc = LOG[c];
    for (size_t i = 0; i < len; ++i) if (v[i]) v[i] = EXP[lc + LOG[v[i]]];
}

void ecc_parity(const uint8_t* const* data, int nd, uint8_t* const* parity, int np, size_t len) {
    gf_init();
    for (int r = 0; r < np; ++r) {
        memset(parity[r], 0, len);
        for (int j = 0; j < nd; ++j) axpy(parity[r], data[j], cauchy(r, np + j), len);
    }
}

/* Solve A x = B in place (A t*t row-major, B t rows of len bytes). */
static int gf_solve(uint8_t* A, uint8_t* B, int t, size_t len) {
    for (int c = 0; c < t; ++c) {
        int p = c; while (p < t && !A[p * t + c]) ++p;
        if (p == t) return -1;
        if (p != c) {
            for (int k = 0; k < t; ++k) { uint8_t tmp = A[c * t + k]; A[c * t + k] = A[p * t + k]; A[p * t + k] = tmp; }
            for (size_t k = 0; k < len; ++k) { uint8_t tmp = B[c * len + k]; B[c * len + k] = B[p * len + k]; B[p * len + k] = tmp; }
        }
        uint8_t iv = ginv(A[c * t + c]);
        for (int k = 0; k < t; ++k) A[c * t + k] = gmul(A[c * t + k], iv);
        scale(B + c * len, iv, len);
        for (int r = 0; r < t; ++r) {
            if (r == c || !A[r * t + c]) continue;
            uint8_t f = A[r * t + c];
            for (int k = 0; k < t; ++k) A[r * t + k] ^= gmul(f, A[c * t + k]);
            axpy(B + r * len, B + c * len, f, len);
        }
    }
    return 0;
}

int ecc_recover(uint8_t* const* data, int nd, const int* miss, int ne,
                const uint8_t* const* parity, const int* prow, int np, size_t len) {
    gf_init();
    if (ne == 0) return 0;
    uint8_t* A = (uint8_t*)malloc((size_t)ne * ne);
    uint8_t* B = (uint8_t*)malloc((size_t)ne * len);
    uint8_t* isMiss = (uint8_t*)calloc((size_t)nd, 1);
    if (!A || !B || !isMiss) { free(A); free(B); free(isMiss); return -1; }
    for (int i = 0; i < ne; ++i) isMiss[miss[i]] = 1;
    for (int i = 0; i < ne; ++i) {
        int r = prow[i];
        memcpy(B + i * len, parity[i], len);
        for (int j = 0; j < nd; ++j) if (!isMiss[j]) axpy(B + i * len, data[j], cauchy(r, np + j), len);
        for (int c = 0; c < ne; ++c) A[i * ne + c] = cauchy(r, np + miss[c]);
    }
    int rc = gf_solve(A, B, ne, len);
    if (!rc) for (int c = 0; c < ne; ++c) memcpy(data[miss[c]], B + c * len, len);
    free(A); free(B); free(isMiss);
    return rc;
}

size_t disp_frag_size(size_t Dn, int k) { return (Dn + (size_t)k - 1) / (size_t)k; }

void disp_encode(const uint8_t* D, size_t Dn, int k, int nf, uint8_t* frag) {
    gf_init();
    size_t F = disp_frag_size(Dn, k);
    memset(frag, 0, (size_t)k * F);
    memcpy(frag, D, Dn);                                  /* systematic part, zero-padded */
    const uint8_t* dp[ECC_MAX]; uint8_t* pp[ECC_MAX];
    for (int j = 0; j < k; ++j) dp[j] = frag + (size_t)j * F;
    for (int r = 0; r < nf - k; ++r) pp[r] = frag + (size_t)(k + r) * F;
    ecc_parity(dp, k, pp, nf - k, F);
}

int disp_decode(const uint8_t* frag, const uint8_t* have, int k, int nf, size_t Dn, uint8_t* D) {
    gf_init();
    size_t F = disp_frag_size(Dn, k);
    uint8_t* buf = (uint8_t*)malloc((size_t)k * F);
    if (!buf) return -1;
    uint8_t* dp[ECC_MAX]; int miss[ECC_MAX], ne = 0;
    for (int j = 0; j < k; ++j) {
        dp[j] = buf + (size_t)j * F;
        if (have[j]) memcpy(dp[j], frag + (size_t)j * F, F); else miss[ne++] = j;
    }
    const uint8_t* pp[ECC_MAX]; int prow[ECC_MAX], got = 0;
    for (int r = 0; r < nf - k && got < ne; ++r)
        if (have[k + r]) { pp[got] = frag + (size_t)(k + r) * F; prow[got] = r; ++got; }
    int rc = -1;
    if (got == ne) rc = ecc_recover(dp, k, miss, ne, pp, prow, nf - k, F);
    if (!rc) memcpy(D, buf, Dn);
    free(buf);
    return rc;
}
