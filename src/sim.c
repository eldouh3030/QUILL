/* Loss model, analytic verifiability, parameter optimisation, and Monte-Carlo
   comparison with stream-signature baselines.

   Channel: Gilbert-Elliott (two-state Markov) over BLE link packets with a
   244-byte ATT payload; a protocol frame longer than that is segmented and is
   received only if every segment is received.

   usage:
     sim validate              real protocol vs analytic model    -> stdout CSV
     sim optimise <payload> [n] best (m,k) per signature and n     -> stdout CSV
     sim compare  <payload>    Monte-Carlo comparison of schemes  -> stdout CSV */
#include "quill.h"
#include "ecc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define MTU 244            /* ATT payload per BLE notification (DLE, ATT_MTU 247) */
#define LL_OVH 21          /* preamble 1 + AA 4 + LL hdr 2 + L2CAP 4 + ATT 3 + MIC 4 + CRC 3 */

/* ---------------------------------------------------------------- channel */
typedef struct { double pgb, pbg; int bad; uint64_t s; } ge_t;
static double urand(ge_t* g) { g->s ^= g->s << 13; g->s ^= g->s >> 7; g->s ^= g->s << 17; return (double)(g->s >> 11) / 9007199254740992.0; }
static void ge_init(ge_t* g, double p, double burst, uint64_t seed) {
    g->s = seed * 0x9E3779B97F4A7C15ull + 1;
    if (p <= 0) { g->pgb = 0; g->pbg = 1; }
    else { g->pbg = 1.0 / burst; g->pgb = p * g->pbg / (1 - p); }
    g->bad = urand(g) < p;
}
/* one link packet: returns 1 if lost */
static int ge_lost(ge_t* g) {
    int lost = g->bad;
    double u = urand(g);
    g->bad = g->bad ? (u >= g->pbg) : (u < g->pgb);
    return lost;
}
static int segs(size_t len) { return (int)((len + MTU - 1) / MTU); }
static int frame_ok(ge_t* g, size_t len) { int ok = 1, s = segs(len); for (int i = 0; i < s; ++i) if (ge_lost(g)) ok = 0; return ok; }
static double air(size_t len) { return (double)len + LL_OVH * segs(len); }

/* -------------------------------------------- analytic model (our scheme) */
/* P(batch verifiable) = P(at most m of n frames lost in batch b AND at least
   k of the n frames of batch b+1 received). Exact Markov computation; each
   frame occupies `sg` link packets and is lost if any of them is lost. */
static void frame_trans(int sg, double pgb, double pbg, double Tok[2][2], double Tlo[2][2]) {
    /* state at the first segment x -> state at the first segment of the next frame y */
    for (int x = 0; x < 2; ++x) {
        double ok[2] = { 0, 0 }, lo[2] = { 0, 0 };   /* indexed by current state, "all good so far" vs "lost" */
        if (x == 0) ok[0] = 1; else lo[1] = 1;
        for (int t = 0; t < sg; ++t) {
            double nok[2] = { 0, 0 }, nlo[2] = { 0, 0 };
            for (int c = 0; c < 2; ++c) {
                double pb = c ? (1 - pbg) : pgb;      /* next segment bad */
                /* transition to next segment state; the next segment (if any) is lost if bad */
                if (t + 1 < sg) {
                    nok[0] += ok[c] * (1 - pb); nlo[1] += ok[c] * pb;
                    nlo[0] += lo[c] * (1 - pb); nlo[1] += lo[c] * pb;
                } else {
                    nok[0] += ok[c] * (1 - pb); nok[1] += ok[c] * pb;
                    nlo[0] += lo[c] * (1 - pb); nlo[1] += lo[c] * pb;
                }
            }
            memcpy(ok, nok, sizeof ok); memcpy(lo, nlo, sizeof lo);
        }
        for (int y = 0; y < 2; ++y) { Tok[x][y] = ok[y]; Tlo[x][y] = lo[y]; }
    }
}
static double p_ok_seg(int n, int m, int k, double p, double burst, int sg) {
    if (p <= 0) return 1.0;
    double pbg = 1.0 / burst, pgb = p * pbg / (1 - p);
    double Tok[2][2], Tlo[2][2]; frame_trans(sg, pgb, pbg, Tok, Tlo);
    int L = m + 2, R = n + 1;
    double* A = calloc((size_t)2 * L * R, sizeof(double)), *B = calloc((size_t)2 * L * R, sizeof(double));
#define IX(s, l, r) (((s) * L + (l)) * R + (r))
    A[IX(0, 0, 0)] = 1 - p; A[IX(1, 0, 0)] = p;          /* stationary state at the first frame */
    for (int t = 0; t < 2 * n; ++t) {
        memset(B, 0, sizeof(double) * 2 * L * R);
        for (int s = 0; s < 2; ++s) for (int l = 0; l < L; ++l) for (int r = 0; r < R; ++r) {
            double v = A[IX(s, l, r)]; if (v == 0) continue;
            for (int y = 0; y < 2; ++y) {
                /* frame received */
                int l2 = l, r2 = r + (t >= n);
                B[IX(y, l2, r2)] += v * Tok[s][y];
                /* frame lost */
                l2 = t < n ? (l + 1 > m + 1 ? m + 1 : l + 1) : l; r2 = r;
                B[IX(y, l2, r2)] += v * Tlo[s][y];
            }
        }
        double* T = A; A = B; B = T;
    }
    double ok = 0;
    for (int s = 0; s < 2; ++s) for (int l = 0; l <= m; ++l) for (int r = k; r < R; ++r) ok += A[IX(s, l, r)];
    free(A); free(B);
    return ok;
#undef IX
}
static double p_ok(int n, int m, int k, double p, double burst) { return p_ok_seg(n, m, k, p, burst, 1); }

/* ------------------------------------------------------- frame sizes */
static size_t siglen_of(int id) { return sig_info(id)->sig_len; }
static size_t ours_frag(int sig, int n, int m, int k) {
    size_t D = siglen_of(sig) + (size_t)(m < n ? m : n) * QUILL_LEAF;
    return (D + k - 1) / k;
}
static size_t ours_frame(int sig, int n, int m, int k, int payload) { return QUILL_HDR_DATA + ours_frag(sig, n, m, k) + payload + QUILL_TAG; }

/* ------------------------------------------------------------- validate */
typedef struct { ge_t* ch; quill_gw_t* g; } chan_ctx_t;
static void emit_ch(void* c, const uint8_t* f, size_t n, int kind) {
    chan_ctx_t* x = c;
    if (kind == 0) { quill_gw_recv(x->g, f, n); return; }  /* session set-up assumed reliable (acknowledged) */
    if (frame_ok(x->ch, n)) quill_gw_recv(x->g, f, n);
}
static void validate(void) {
    printf("signature,n,m,k,loss,burst,batches,measured_ok,model_ok,abs_diff\n");
    kem_gw_t* kg = kem_gw_keygen(KEM_MLKEM512);
    sig_key_t* sk = sig_keygen(SIG_MLDSA44); size_t pkn; const uint8_t* pk = sig_pk(sk, &pkn);
    static const double P[] = { 0.02, 0.05, 0.10, 0.20 }, BU[] = { 1, 4, 10 };
    struct { int n, m, k; } C[] = { { 16, 4, 12 }, { 32, 8, 24 } };
    const int NB = 6000;
    for (unsigned c = 0; c < 2; ++c) for (int pi = 0; pi < 4; ++pi) for (int bi = 0; bi < 3; ++bi) {
        quill_params_t pr = { SIG_MLDSA44, KEM_MLKEM512, C[c].n, C[c].m, C[c].k, 0 };
        ge_t ch; ge_init(&ch, P[pi], BU[bi], 1000 + c * 100 + pi * 10 + bi);
        quill_gw_t g; quill_gw_init(&g, &pr, kg, pk, pkn);
        chan_ctx_t x = { &ch, &g };
        quill_dev_t d; quill_dev_init(&d, &pr, sk, kem_gw_pk(kg), 99, emit_ch, &x);
        uint8_t pl[16] = { 0 };
        for (int t = 0; t < NB * C[c].n; ++t) quill_dev_send(&d, pl, 16, 0);
        quill_gw_finish(&g);
        /* the last batch has no following batch to carry its fragments: exclude it */
        double meas = (double)g.batches_ok / (NB - 1);
        if (meas > 1) meas = 1;
        double mod = p_ok_seg(C[c].n, C[c].m, C[c].k, P[pi], BU[bi], segs(ours_frame(SIG_MLDSA44, C[c].n, C[c].m, C[c].k, 16)));
        printf("%s,%d,%d,%d,%.2f,%.0f,%d,%.4f,%.4f,%.4f\n", sig_info(SIG_MLDSA44)->name, C[c].n, C[c].m, C[c].k,
               P[pi], BU[bi], NB - 1, meas, mod, fabs(meas - mod));
        fflush(stdout);
        quill_dev_free(&d); quill_gw_free(&g);
    }
}

/* ------------------------------------------------------------- optimise */
/* minimise air bytes per packet s.t. P(batch verifiable) >= target and
   NR delay (n + expected k-th arrival) <= maxdelay packet periods */
static int SIGS[] = { SIG_MLDSA44, SIG_FALCON512, SIG_SPHINCS128S, SIG_SPHINCS128F, SIG_LMS, SIG_ED25519 };
#define NSIGS 6
typedef struct { int n, m, k; double ovh, pok; } best_t;
static best_t optimise(int sig, int payload, double p, double burst, double target, int n) {
    best_t b = { n, 0, 0, 1e18, 0 };
    for (int m = 0; m < n && m <= 96; ++m) {
        if (p_ok_seg(n, m, 1, p, burst, 1) < target) continue;
        /* larger k = smaller fragments but needs more arrivals; frame segmentation
           depends on k, so scan k downward and keep the first that meets the target */
        for (int kk = n; kk >= 1; --kk) {
            size_t fl = ours_frame(sig, n, m, kk, payload);
            double ovh = air(fl) - payload;
            if (ovh >= b.ovh) break;                      /* smaller k only grows the frame */
            double po = p_ok_seg(n, m, kk, p, burst, segs(fl));
            if (po >= target) { b.m = m; b.k = kk; b.ovh = ovh; b.pok = po; break; }
        }
    }
    if (b.ovh > 1e17) b.n = 0;
    return b;
}
static void optimise_all(int payload, int nonly) {
    printf("signature,payload,n,loss,burst,target,m,k,frag_bytes,frame_bytes,air_overhead_per_packet,p_ok\n");
    static const double P[] = { 0.0, 0.01, 0.02, 0.05, 0.10, 0.15, 0.20, 0.30 }, BU[] = { 1, 4, 10 };
    static const int NS[] = { 16, 32, 64, 128 };
    for (int s = 0; s < NSIGS; ++s) for (int ni = 0; ni < 4; ++ni) for (int bi = 0; bi < 3; ++bi) for (int pi = 0; pi < 8; ++pi) {
        int n = NS[ni]; if (nonly && n != nonly) continue;
        if (P[pi] == 0 && bi > 0) continue;
        best_t b = optimise(SIGS[s], payload, P[pi], BU[bi], 0.99, n);
        printf("%s,%d,%d,%.2f,%.0f,0.99,%d,%d,%zu,%zu,%.1f,%.4f\n", sig_info(SIGS[s])->name, payload, n, P[pi], BU[bi],
               b.m, b.k, b.n ? ours_frag(SIGS[s], n, b.m, b.k) : 0, b.n ? ours_frame(SIGS[s], n, b.m, b.k, payload) : 0,
               b.n ? b.ovh : -1.0, b.pok);
        fflush(stdout);
    }
}

/* -------------------------------------------------------------- compare */
/* Monte-Carlo over NB batches. Returns verified fraction of received data
   packets, air bytes per packet, mean NR delay (packet periods). */
typedef struct { double vf, bytes, delay, rxf, vsent; } res_t;
enum { S_OURS, S_OURS_OPT, S_SAIDA, S_BATCH1, S_BATCH2, S_EMSS, S_EACH, S_NUM };
static const char* SNAME[] = { "Proposed (fixed m and k)", "Proposed (m and k tuned)", "Leaf list coded (SAIDA-style)", "Batch signature x1", "Batch signature x2", "EMSS (2 links; signature x2)", "Sign each packet" };

static res_t mc(int scheme, int sig, int payload, int n, int m, int k, double p, double burst, int NB, uint64_t seed) {
    ge_t ch; ge_init(&ch, p, burst, seed);
    size_t sl = siglen_of(sig);
    double bytes = 0, dsum = 0; long rx = 0, ver = 0, dn = 0;
    int* got = malloc(sizeof(int) * (NB + 1) * n);
    long sent = 0;
    if (scheme == S_OURS || scheme == S_OURS_OPT || scheme == S_SAIDA) {
        int mm = scheme == S_SAIDA ? n : m;
        size_t fl = ours_frame(sig, n, mm, k, payload);
        int* fr = malloc(sizeof(int) * (NB + 1));            /* fragments of batch b received (in batch b+1) */
        int* kth = malloc(sizeof(int) * (NB + 1));           /* position of k-th fragment arrival */
        for (int b = 0; b <= NB; ++b) {
            fr[b] = 0; kth[b] = -1;
            for (int i = 0; i < n; ++i) {
                int ok = frame_ok(&ch, fl); bytes += air(fl);
                got[b * n + i] = ok;
                if (b > 0 && ok && ++fr[b - 1] == k) kth[b - 1] = i;
            }
        }
        for (int b = 0; b < NB; ++b) {
            int lost = 0; for (int i = 0; i < n; ++i) lost += !got[b * n + i];
            int okb = lost <= mm && fr[b] >= k;
            for (int i = 0; i < n; ++i) if (got[b * n + i]) { rx++; if (okb) { ver++; dsum += (n - i) + kth[b]; dn++; } }
        }
        sent = (long)NB * n;
        bytes /= (double)(NB + 1) * n;
        free(fr); free(kth);
    } else if (scheme == S_BATCH1 || scheme == S_BATCH2) {
        int rep = scheme == S_BATCH1 ? 1 : 2;
        size_t dl = 10 + payload + QUILL_TAG, sf = QUILL_HDR_AUX + sl + (size_t)n * QUILL_LEAF;
        for (int b = 0; b < NB; ++b) {
            for (int i = 0; i < n; ++i) { got[b * n + i] = frame_ok(&ch, dl); bytes += air(dl); }
            int okb = 0; for (int r = 0; r < rep; ++r) { okb |= frame_ok(&ch, sf); bytes += air(sf); }
            for (int i = 0; i < n; ++i) if (got[b * n + i]) { rx++; if (okb) { ver++; dsum += n - i; dn++; } }
        }
        sent = (long)NB * n;
        bytes /= (double)NB * n;
    } else if (scheme == S_EMSS) {
        /* packet i carries H(P_{i-1}) and H(P_{i-3}); the signature packet signs H(P_{n-1}), H(P_{n-2}) and is sent twice */
        size_t dl = 10 + payload + QUILL_TAG + 2 * QUILL_LEAF, sf = QUILL_HDR_AUX + sl + 2 * QUILL_LEAF;
        int ver_i[QUILL_MAX_N];
        for (int b = 0; b < NB; ++b) {
            for (int i = 0; i < n; ++i) { got[b * n + i] = frame_ok(&ch, dl); bytes += air(dl); }
            int okb = 0; for (int r = 0; r < 2; ++r) { okb |= frame_ok(&ch, sf); bytes += air(sf); }
            for (int i = n - 1; i >= 0; --i) {
                int v = 0;
                if (got[b * n + i]) {
                    if (okb && (i == n - 1 || i == n - 2)) v = 1;
                    if (i + 1 < n && got[b * n + i + 1] && ver_i[i + 1]) v = 1;
                    if (i + 3 < n && got[b * n + i + 3] && ver_i[i + 3]) v = 1;
                }
                ver_i[i] = v;
            }
            for (int i = 0; i < n; ++i) if (got[b * n + i]) { rx++; if (ver_i[i]) { ver++; dsum += n - i; dn++; } }
        }
        sent = (long)NB * n;
        bytes /= (double)NB * n;
    } else { /* S_EACH */
        size_t dl = 10 + payload + QUILL_TAG + sl;
        for (long t = 0; t < (long)NB * n; ++t) { int ok = frame_ok(&ch, dl); bytes += air(dl); if (ok) { rx++; ver++; dn++; } }
        sent = (long)NB * n;
        bytes /= (double)NB * n;
    }
    free(got);
    res_t r = { rx ? (double)ver / rx : 0, bytes, dn ? dsum / dn : 0, (double)rx / sent, (double)ver / sent };
    return r;
}

static void compare_all(int payload) {
    printf("scheme,signature,payload,n,m,k,loss,burst,delivered_fraction,verified_of_delivered,verified_of_sent,air_bytes_per_packet,overhead_per_packet,nr_delay_packets\n");
    static const double P[] = { 0.0, 0.01, 0.02, 0.05, 0.10, 0.15, 0.20, 0.30 }, BU[] = { 1, 4 };
    int sigs[] = { SIG_MLDSA44, SIG_FALCON512, SIG_LMS };
    const int n = 32, m = 8, k = 22, NB = 4000;
    for (int s = 0; s < 3; ++s) for (int sc = 0; sc < S_NUM; ++sc) for (int bi = 0; bi < 2; ++bi) for (int pi = 0; pi < 8; ++pi) {
        if (P[pi] == 0 && bi > 0) continue;
        int nb = sc == S_EACH ? 300 : NB, mm = m, kk = k;
        if (sc == S_OURS_OPT) { best_t b = optimise(sigs[s], payload, P[pi], BU[bi], 0.99, n); if (!b.n) continue; mm = b.m; kk = b.k; }
        res_t r = mc(sc, sigs[s], payload, n, mm, kk, P[pi], BU[bi], nb, 77 + pi * 7 + bi);
        printf("%s,%s,%d,%d,%d,%d,%.2f,%.0f,%.4f,%.4f,%.4f,%.1f,%.1f,%.1f\n", SNAME[sc], sig_info(sigs[s])->name, payload, n,
               (sc == S_OURS || sc == S_OURS_OPT) ? mm : sc == S_SAIDA ? n : 0, (sc == S_OURS || sc == S_OURS_OPT || sc == S_SAIDA) ? kk : 0,
               P[pi], BU[bi], r.rxf, r.vf, r.vsent, r.bytes, r.bytes - payload, r.delay);
        fflush(stdout);
    }
}


/* ---------------------------------------------------------------- adaptive */
/* A channel that switches between a calm and a noisy regime (posture or
   movement changes), and three policies for (m, k): fixed for the calm
   regime, fixed for the noisy regime, and adaptive. In the adaptive policy the
   gateway reports after every batch how many of its frames were lost and the
   mean burst length; the device keeps moving averages and, before closing a
   batch, picks (m, k) from a table computed with the exact model. */
#ifndef ADAPT_TARGET
#define ADAPT_TARGET 0.995   /* the table aims a little higher to absorb the lag of the estimate */
#endif
#define NGP 11
#define NGB 5
static const double GP[NGP] = { 0.005, 0.01, 0.02, 0.03, 0.05, 0.07, 0.10, 0.15, 0.20, 0.25, 0.30 }, GB[NGB] = { 1, 2, 4, 6, 10 };
static void adaptive_all(int payload) {
    const int n = 32, NB = 20000; const int sigs[] = { SIG_MLDSA44, SIG_FALCON512 };
    struct { const char* name; double p1, b1, p2, b2, sw; } CH[] = {
        { "calm 1% / noisy 15% (bursts 2 / 6)", 0.01, 2, 0.15, 6, 0.05 },
        { "calm 2% / noisy 10% (bursts 2 / 4)", 0.02, 2, 0.10, 4, 0.05 },
        { "calm 1% / noisy 30% (bursts 2 / 10)", 0.01, 2, 0.30, 10, 0.02 },
    };
    printf("signature,channel,policy,verified_of_delivered,verified_of_sent,air_bytes_per_packet,overhead_per_packet\n");
    for (unsigned si = 0; si < 2; ++si) {
        int sig = sigs[si];
        int TM[NGP][NGB], TK[NGP][NGB];
        for (int a = 0; a < NGP; ++a) for (int c = 0; c < NGB; ++c) {
            best_t b = optimise(sig, payload, GP[a], GB[c], ADAPT_TARGET, n);
            if (!b.n) { TM[a][c] = -1; TK[a][c] = -1; continue; }     /* target not reachable: use the nearest feasible entry */
            TM[a][c] = b.m; TK[a][c] = b.k;
        }
        best_t calm, noisy;
        for (unsigned ci = 0; ci < sizeof CH / sizeof *CH; ++ci) {
            calm = optimise(sig, payload, CH[ci].p1, CH[ci].b1, 0.99, n);
            noisy = optimise(sig, payload, CH[ci].p2, CH[ci].b2, 0.99, n);
            if (!noisy.n) { noisy.m = n - 1; noisy.k = 1; }
            for (int pol = 0; pol < 3; ++pol) {
                ge_t ch1, ch2; ge_init(&ch1, CH[ci].p1, CH[ci].b1, 900 + ci); ge_init(&ch2, CH[ci].p2, CH[ci].b2, 950 + ci);
                uint64_t rs = 4242 + ci; int regime = 0;
                double pe = CH[ci].p1, be = 1.5;              /* device estimates (adaptive) */
                int *got = malloc(sizeof(int) * (NB + 1) * n), *mm = malloc(sizeof(int) * (NB + 1)), *kk = malloc(sizeof(int) * (NB + 1));
                int* fr = calloc(NB + 1, sizeof(int)); double bytes = 0; long rx = 0, ver = 0;
                for (int b = 0; b <= NB; ++b) {
                    /* parameters of batch b, chosen before it closes */
                    if (pol == 0) { mm[b] = calm.m; kk[b] = calm.k; }
                    else if (pol == 1) { mm[b] = noisy.m; kk[b] = noisy.k; }
                    else {
                        int a = 0; while (a < NGP - 1 && GP[a] < pe) ++a;          /* round up */
                        int c = 0; while (c < NGB - 1 && GB[c] < be) ++c;
                        while (TM[a][c] < 0 && (a > 0 || c > 0)) { if (c > 0) --c; else --a; }
                        mm[b] = TM[a][c]; kk[b] = TK[a][c];
                    }
                    size_t fl = b > 0 ? ours_frame(sig, n, mm[b - 1], kk[b - 1], payload) : (size_t)(QUILL_HDR_DATA + payload + QUILL_TAG);
                    int lost = 0, runs = 0, prev = 0;
                    for (int i = 0; i < n; ++i) {
                        rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17;
                        if ((double)(rs >> 11) / 9007199254740992.0 < CH[ci].sw / n) regime ^= 1;   /* regime switch */
                        int ok = frame_ok(regime ? &ch2 : &ch1, fl); bytes += air(fl);
                        got[b * n + i] = ok;
                        if (b > 0 && ok) fr[b - 1]++;
                        if (!ok) { lost++; if (!prev) runs++; }
                        prev = !ok;
                    }
                    /* gateway feedback after the batch (one small frame per batch, counted) */
                    if (pol == 2) {
                        bytes += air(4);
                        double pl = (double)lost / n, bl = runs ? (double)lost / runs : 1.0;
                        pe = 0.5 * pe + 0.5 * pl;
                        if (runs) be = 0.5 * be + 0.5 * bl;
                    }
                }
                for (int b = 0; b < NB; ++b) {
                    int lost = 0; for (int i = 0; i < n; ++i) lost += !got[b * n + i];
                    int me = mm[b] < n ? mm[b] : n;
                    int okb = lost <= me && fr[b] >= kk[b];
                    for (int i = 0; i < n; ++i) if (got[b * n + i]) { rx++; if (okb) ver++; }
                }
                bytes /= (double)(NB + 1) * n;
                static const char* PN[] = { "fixed for the calm regime", "fixed for the noisy regime", "adaptive (gateway feedback)" };
                printf("%s,%s,%s,%.4f,%.4f,%.1f,%.1f\n", sig_info(sig)->name, CH[ci].name, PN[pol], (double)ver / rx, (double)ver / ((double)NB * n), bytes, bytes - payload);
                fflush(stdout);
                free(got); free(mm); free(kk); free(fr);
            }
        }
    }
}

/* fair comparison: SAIDA-style dispersal of all n leaves (m = n) with k tuned to
   the same target, against QUILL with m and k tuned */
static void fair_all(int payload) {
    printf("signature,n,loss,burst,quill_m,quill_k,quill_overhead,full_k,full_overhead,saving_bytes\n");
    static const double P[] = { 0.01, 0.02, 0.05, 0.10, 0.20 }, BU[] = { 1, 4 };
    int sigs[] = { SIG_MLDSA44, SIG_FALCON512, SIG_LMS };
    for (int s = 0; s < 3; ++s) for (int n = 32; n <= 64; n *= 2) for (int bi = 0; bi < 2; ++bi) for (int pi = 0; pi < 5; ++pi) {
        best_t q = optimise(sigs[s], payload, P[pi], BU[bi], 0.99, n);
        /* full list: m = n, scan k */
        double fo = 1e18; int fk = 0;
        for (int kk = n; kk >= 1; --kk) {
            size_t fl = ours_frame(sigs[s], n, n, kk, payload); double o = air(fl) - payload;
            if (o >= fo) break;
            if (p_ok_seg(n, n, kk, P[pi], BU[bi], segs(fl)) >= 0.99) { fo = o; fk = kk; break; }
        }
        printf("%s,%d,%.2f,%.0f,%d,%d,%.1f,%d,%.1f,%.1f\n", sig_info(sigs[s])->name, n, P[pi], BU[bi], q.m, q.k, q.n ? q.ovh : -1, fk, fk ? fo : -1, (q.n && fk) ? fo - q.ovh : 0);
        fflush(stdout);
    }
}

int main(int argc, char** argv) {
    crypto_init(); gf_init();
    sig_info(0);
    { sig_key_t* lk = sig_keygen(SIG_LMS); (void)lk; }        /* fixes the LMS signature length */
    if (argc < 2) { fprintf(stderr, "usage: sim validate | optimise <payload> [maxn] | compare <payload>\n"); return 1; }
    if (!strcmp(argv[1], "validate")) validate();
    else if (!strcmp(argv[1], "optimise")) optimise_all(argc > 2 ? atoi(argv[2]) : 16, argc > 3 ? atoi(argv[3]) : 0);
    else if (!strcmp(argv[1], "compare")) compare_all(argc > 2 ? atoi(argv[2]) : 16);
    else if (!strcmp(argv[1], "adaptive")) adaptive_all(argc > 2 ? atoi(argv[2]) : 16);
    else if (!strcmp(argv[1], "fair")) fair_all(argc > 2 ? atoi(argv[2]) : 16);
    else if (!strcmp(argv[1], "pok")) {   /* sim pok n m k p burst */
        printf("%.6f\n", p_ok(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atof(argv[5]), atof(argv[6])));
    }
    return 0;
}
