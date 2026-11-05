/* Host (laptop / gateway) timing of the primitives and of the protocol steps.
   usage: hostbench [max_reps] [seconds_per_op] > primitives.csv
   Output: scheme,operation,reps,mean_us,sd_us,median_us,p95_us */
#include "quill.h"
#include "ecc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
static double now_us(void) { LARGE_INTEGER f, c; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c); return (double)c.QuadPart * 1e6 / (double)f.QuadPart; }
#else
static double now_us(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e6 + t.tv_nsec / 1e3; }
#endif

static int MAXR = 1000; static double BUDGET = 3e6;
static double* V;
static int cmpd(const void* a, const void* b) { double x = *(const double*)a, y = *(const double*)b; return x < y ? -1 : x > y; }
static void report(const char* scheme, const char* op, double* v, int n) {
    qsort(v, n, sizeof *v, cmpd);
    double s = 0, s2 = 0; for (int i = 0; i < n; ++i) { s += v[i]; s2 += v[i] * v[i]; }
    double mean = s / n, var = n > 1 ? (s2 - n * mean * mean) / (n - 1) : 0;
    int i95 = (int)ceil(0.95 * n) - 1; if (i95 < 0) i95 = 0;
    printf("%s,%s,%d,%.2f,%.2f,%.2f,%.2f\n", scheme, op, n, mean, var > 0 ? sqrt(var) : 0, v[n / 2], v[i95]);
    fprintf(stderr, "%-24s %-22s %6d  %12.2f us\n", scheme, op, n, mean);
    fflush(stdout);
}
#define TIME(SCHEME, OP, BODY) do { double t0g = now_us(); int n_ = 0; \
    for (; n_ < MAXR && (n_ < 3 || now_us() - t0g < BUDGET); ++n_) { double t0 = now_us(); BODY; V[n_] = now_us() - t0; } \
    report(SCHEME, OP, V, n_); } while (0)

typedef struct { uint8_t* f[512]; size_t n[512]; int cnt; } wire_t;
static void emit(void* c, const uint8_t* f, size_t n, int kind) {
    (void)kind; wire_t* w = c; if (w->cnt < 512) { w->f[w->cnt] = malloc(n); memcpy(w->f[w->cnt], f, n); w->n[w->cnt++] = n; }
}

int main(int argc, char** argv) {
    if (argc > 1) MAXR = atoi(argv[1]);
    if (argc > 2) BUDGET = atof(argv[2]) * 1e6;
    V = malloc(sizeof(double) * (MAXR + 8));
    crypto_init(); gf_init();
    printf("scheme,operation,reps,mean_us,sd_us,median_us,p95_us\n");

    uint8_t msg[78]; memset(msg, 0x5a, sizeof msg);
    uint8_t key[32], iv[12] = { 0 }, pl[256], ct[512], h[32];
    memset(key, 1, 32); memset(pl, 2, sizeof pl);
    TIME("AES-256-GCM", "encrypt 64 B", gcm_enc(key, iv, msg, 10, pl, 64, ct));
    TIME("AES-256-GCM", "encrypt 96 B", gcm_enc(key, iv, msg, 10, pl, 96, ct));
    TIME("SHA-256", "hash 128 B", h256(pl, 128, h));
    TIME("HKDF-SHA-256", "derive 32 B", hkdf(key, 32, NULL, 0, msg, 8, h, 32));

    for (int lvl = 0; lvl < 2; ++lvl) {
        const char* nm = lvl ? "X25519+ML-KEM-768" : "X25519+ML-KEM-512";
        kem_gw_t* g = NULL; uint8_t c[KEM_MAX_CT], ss[32];
        TIME(nm, "gateway keygen", { g = kem_gw_keygen(lvl); });
        TIME(nm, "encapsulate", kem_encaps(lvl, kem_gw_pk(g), c, ss));
        TIME(nm, "decapsulate", kem_decaps(g, c, ss));
    }

    static const int ids[] = { SIG_MLDSA44, SIG_MLDSA44_REF, SIG_FALCON512, SIG_SPHINCS128S, SIG_SPHINCS128F, SIG_LMS, SIG_ED25519 };
    for (unsigned t = 0; t < sizeof ids / sizeof *ids; ++t) {
        int id = ids[t]; const char* nm = sig_info(id)->name;
        sig_key_t* k = NULL;
        int saveR = MAXR; if (id == SIG_LMS) MAXR = 3;
        TIME(nm, "keygen", { k = sig_keygen(id); });
        MAXR = saveR;
        size_t pkn; const uint8_t* pk = sig_pk(k, &pkn);
        size_t sl = sig_info(id)->sig_len; uint8_t* s = malloc(sl + 64); size_t got = sl + 64;
        TIME(nm, "sign", { got = sl + 64; sig_sign(k, msg, sizeof msg, s, &got); });
        TIME(nm, "verify", { if (sig_verify(id, pk, pkn, msg, sizeof msg, s, got)) { fprintf(stderr, "verify failed\n"); exit(1); } });
        free(s);
    }

    /* protocol: device per-packet work, batch close, gateway receive and settle */
    kem_gw_t* kg = kem_gw_keygen(KEM_MLKEM512);
    for (unsigned t = 0; t < sizeof ids / sizeof *ids; ++t) {
        int id = ids[t]; if (id == SIG_MLDSA44_REF) continue;
        const char* nm = sig_info(id)->name;
        sig_key_t* sk = sig_keygen(id); size_t pkn; const uint8_t* pk = sig_pk(sk, &pkn);
        quill_params_t p = { id, KEM_MLKEM512, 32, 8, 24, 0 };
        int saveR = MAXR; if (id == SIG_SPHINCS128S || id == SIG_SPHINCS128F) MAXR = MAXR < 20 ? MAXR : 20;
        /* device: 31 ordinary packets then one closing packet; repeat */
        double* tp = malloc(sizeof(double) * 40000); int ntp = 0;
        double* tc = malloc(sizeof(double) * (MAXR + 8)); int ntc = 0;
        wire_t* w = calloc(1, sizeof *w);
        quill_dev_t d; quill_dev_init(&d, &p, sk, kem_gw_pk(kg), 1, NULL, NULL);
        double tg = now_us();
        while (ntc < MAXR && (ntc < 3 || now_us() - tg < BUDGET)) {
            for (int i = 0; i < 32; ++i) {
                double t0 = now_us(); quill_dev_send(&d, pl, 16, 0); double dt = now_us() - t0;
                if (i < 31) { if (ntp < 40000) tp[ntp++] = dt; } else tc[ntc++] = dt;
            }
        }
        report(nm, "device packet (16 B)", tp, ntp);
        report(nm, "device batch close n=32", tc, ntc);
        quill_dev_free(&d);
        /* gateway: receive two batches and verify the first */
        quill_dev_init(&d, &p, sk, kem_gw_pk(kg), 1, emit, w);
        for (int i = 0; i < 64; ++i) quill_dev_send(&d, pl, 16, 0);
        quill_dev_free(&d);
        double* tr = malloc(sizeof(double) * 40000); int ntr = 0;
        double* ts = malloc(sizeof(double) * (MAXR + 8)); int nts = 0;
        tg = now_us();
        while (nts < MAXR && (nts < 3 || now_us() - tg < BUDGET)) {
            quill_gw_t g; quill_gw_init(&g, &p, kg, pk, pkn);
            quill_gw_recv(&g, w->f[0], w->n[0]);
            for (int j = 1; j <= 32; ++j) {
                if (j >= 5 && j < 13) continue;          /* 8 losses in batch 0 (= m) */
                double t0 = now_us(); quill_gw_recv(&g, w->f[j], w->n[j]); if (ntr < 40000) tr[ntr++] = now_us() - t0;
            }
            for (int j = 33; j <= 55; ++j) quill_gw_recv(&g, w->f[j], w->n[j]);   /* 23 fragments */
            double t0 = now_us(); quill_gw_recv(&g, w->f[56], w->n[56]); ts[nts++] = now_us() - t0;  /* 24th: decode+verify */
            if (g.batches_ok != 1) { fprintf(stderr, "gateway verify failed\n"); exit(1); }
            quill_gw_free(&g);
        }
        report(nm, "gateway packet", tr, ntr);
        report(nm, "gateway settle (8 lost)", ts, nts);
        for (int j = 0; j < w->cnt; ++j) free(w->f[j]);
        free(w); free(tp); free(tc); free(tr); free(ts);
        MAXR = saveR;
    }
    return 0;
}
