/* Real-data streams through the protocol over a lossy BLE link.

   ECG : MIT-BIH record 100, lead MLII, 360 Hz; 64 samples per packet packed
         as 12-bit values (96-byte payload), one packet every 177.8 ms.
   Vitals: MIMIC numerics (HR, SpO2, SYS, DIA, RESP), 16-byte payload,
         replayed at one record per second; a record outside the alarm limits
         (HR < 40 or > 130 /min, SpO2 < 90 %, RESP < 8 or > 30 /min) is urgent
         and closes its batch at once.

   usage: stream <ecg|vitals> <datafile> <sig> <n> <m> <k> <loss> <burst> <mcu.csv> [seed]
   One CSV line on stdout.                                                    */
#include "quill.h"
#include "ecc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define MTU 244
#define LL_OVH 21
#define LINK_PKT_S 0.00125          /* one link packet per 1.25 ms (2M PHY, 7.5 ms interval, 6 packets) */
#define E_CYCLE_NJ 0.155            /* nRF52840 class: 52 uA/MHz at 3 V, 64 MHz */
#define E_BYTE_UJ  0.0576           /* TX 0 dBm, 4.8 mA at 3 V, 2 Mbps: 4 us per byte */
#define F_CPU 64e6

typedef struct { double pgb, pbg; int bad; uint64_t s; } ge_t;
static double urand(ge_t* g) { g->s ^= g->s << 13; g->s ^= g->s >> 7; g->s ^= g->s << 17; return (double)(g->s >> 11) / 9007199254740992.0; }
static void ge_init(ge_t* g, double p, double burst, uint64_t seed) {
    g->s = seed * 0x9E3779B97F4A7C15ull + 1;
    if (p <= 0) { g->pgb = 0; g->pbg = 1; } else { g->pbg = 1.0 / burst; g->pgb = p * g->pbg / (1 - p); }
    g->bad = urand(g) < p;
}
static int ge_lost(ge_t* g) { int l = g->bad; double u = urand(g); g->bad = g->bad ? (u >= g->pbg) : (u < g->pgb); return l; }
static int segs(size_t len) { return (int)((len + MTU - 1) / MTU); }

/* ------------------------------------------------------------ simulation */
typedef struct {
    ge_t ch; quill_gw_t* g;
    double t;                       /* time of the frame being delivered */
    double air_bytes; long frames, aux_frames;
    double* gen_t;                  /* generation time of packet (b, i) */
    int n;
    double* ver_t;                  /* verification time per batch */
    int nbatch;
} sim_t;
static sim_t S;

static void on_batch(void* c, uint32_t b, int nb, int ok, const uint8_t* have) {
    (void)c; (void)nb; (void)have;
    if ((int)b < S.nbatch && ok) S.ver_t[b] = S.t;
}
static void emit(void* c, const uint8_t* f, size_t n, int kind) {
    (void)c;
    if (kind == 0) { quill_gw_recv(S.g, f, n); return; }     /* set-up exchanged reliably */
    int sg = segs(n), ok = 1;
    for (int i = 0; i < sg; ++i) if (ge_lost(&S.ch)) ok = 0;
    S.air_bytes += n + LL_OVH * sg; S.frames++;
    if (kind == 2) { S.aux_frames++; S.t += LINK_PKT_S * sg; }
    if (ok) quill_gw_recv(S.g, f, n);
}

/* MCU cycles from the emulator CSV */
static double mcu_lookup(const char* file, const char* fn, int len, int sig, int n, int m, int k) {
    FILE* f = fopen(file, "r"); if (!f) return -1;
    char line[512]; double best = -1;
    while (fgets(line, sizeof line, f)) {
        char name[64]; int L, sg, nn, mm, kk, reps; double insn, cyc;
        if (sscanf(line, "%63[^,],%d,%d,%d,%d,%d,%d,%lf,%lf", name, &L, &sg, &nn, &mm, &kk, &reps, &insn, &cyc) != 9) continue;
        if (strcmp(name, fn)) continue;
        if ((len < 0 || L == len) && (sig < 0 || sg == sig) && (n < 0 || nn == n) && (m < 0 || mm == m) && (k < 0 || kk == k)) best = cyc;
    }
    fclose(f);
    return best;
}

int main(int argc, char** argv) {
    if (argc < 10) { fprintf(stderr, "usage: stream <ecg|vitals> <datafile> <sig> <n> <m> <k> <loss> <burst> <mcu.csv> [seed]\n"); return 1; }
    int ecg = !strcmp(argv[1], "ecg");
    int sig = atoi(argv[3]), n = atoi(argv[4]), m = atoi(argv[5]), k = atoi(argv[6]);
    double loss = atof(argv[7]), burst = atof(argv[8]);
    uint64_t seed = argc > 10 ? (uint64_t)atoll(argv[10]) : 1;
    crypto_init(); gf_init();

    /* -------- load the workload: payloads, times, urgency */
    int np = 0, plen = ecg ? 96 : 16; uint8_t* pay; double* tgen; uint8_t* urg; double period;
    if (ecg) {
        FILE* f = fopen(argv[2], "rb"); if (!f) { perror("ecg"); return 1; }
        fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
        uint8_t* raw = malloc(sz); if (fread(raw, 1, sz, f) != (size_t)sz) return 1; fclose(f);
        long ns = sz / 3;                                     /* format 212: 3 bytes = 2 samples (MLII, V5) */
        int* mlii = malloc(sizeof(int) * ns);
        for (long i = 0; i < ns; ++i) { int v = raw[3 * i] | ((raw[3 * i + 1] & 0x0f) << 8); mlii[i] = v; }
        np = (int)(ns / 64); period = 64.0 / 360.0;
        pay = malloc((size_t)np * plen); tgen = malloc(sizeof(double) * np); urg = calloc(np, 1);
        for (int p = 0; p < np; ++p) {
            uint8_t* q = pay + (size_t)p * plen;
            for (int j = 0; j < 64; j += 2) {                 /* two 12-bit samples in 3 bytes */
                int a = mlii[p * 64 + j], b = mlii[p * 64 + j + 1];
                q[(j / 2) * 3] = (uint8_t)a; q[(j / 2) * 3 + 1] = (uint8_t)(((a >> 8) & 0x0f) | ((b & 0x0f) << 4)); q[(j / 2) * 3 + 2] = (uint8_t)(b >> 4);
            }
            tgen[p] = (p + 1) * period;
        }
        free(raw); free(mlii);
    } else {
        FILE* f = fopen(argv[2], "r"); if (!f) { perror("vitals"); return 1; }
        char line[256]; int cap = 4096;
        pay = malloc((size_t)cap * plen); tgen = malloc(sizeof(double) * cap); urg = calloc(cap, 1);
        if (!fgets(line, sizeof line, f)) return 1;            /* header */
        period = 1.0;
        while (fgets(line, sizeof line, f) && np < cap) {
            char* fld[8]; int nf = 0; char* s = line;
            for (char* q = line; ; ++q) { if (*q == ',' || *q == '\n' || *q == 0) { int end = *q == 0 || *q == '\n'; *q = 0; if (nf < 8) fld[nf++] = s; s = q + 1; if (end) break; } }
            if (nf < 7) continue;
            int v[6]; for (int j = 0; j < 6; ++j) v[j] = *fld[1 + j] ? atoi(fld[1 + j]) : 0xFFFF;
            uint8_t* q = pay + (size_t)np * plen; memset(q, 0, plen);
            for (int j = 0; j < 6; ++j) { q[2 * j] = (uint8_t)(v[j] >> 8); q[2 * j + 1] = (uint8_t)v[j]; }
            int hr = v[1], sp = v[2], rr = v[5];
            urg[np] = (hr != 0xFFFF && (hr < 40 || hr > 130)) || (sp != 0xFFFF && sp < 90) || (rr != 0xFFFF && (rr < 8 || rr > 30));
            tgen[np] = (np + 1) * period;
            np++;
        }
        fclose(f);
    }

    /* -------- device cycles (emulated Cortex-M4) */
    /* per packet: key derivation, AES-GCM, key commitment, leaf; per batch:
       signature + Merkle root + leaf parity + dispersal + two chain derivations */
    double cyc_pkt = mcu_lookup(argv[9], "op_packet", plen, sig, n, m, k);   /* includes the fragment it carries */
    double cyc_sign = -1;
    { static const char* nm[] = { "op_sign_mldsa44", "op_sign_falcon512", "op_sign_sphincs128s", "op_sign_sphincs128f", "op_sign_lms", "op_sign_ed25519" };
      if (sig < 6) cyc_sign = mcu_lookup(argv[9], nm[sig], -1, -1, -1, -1, -1); }
    double cyc_merkle = mcu_lookup(argv[9], "op_merkle", -1, -1, n, -1, -1);
    double cyc_par = m ? mcu_lookup(argv[9], "op_parity", -1, -1, n, m, -1) : 0;
    double cyc_disp = mcu_lookup(argv[9], "op_disperse", -1, sig, n, m, k);
    double cyc_kdf = mcu_lookup(argv[9], "op_hkdf_expand", -1, -1, -1, -1, -1);
    if (cyc_pkt < 0 || cyc_sign < 0 || cyc_merkle < 0 || cyc_par < 0 || cyc_disp < 0 || cyc_kdf < 0)
        fprintf(stderr, "warning: missing MCU numbers (pkt %.0f sign %.0f merkle %.0f parity %.0f disperse %.0f kdf %.0f)\n",
                cyc_pkt, cyc_sign, cyc_merkle, cyc_par, cyc_disp, cyc_kdf);
    double cyc_close = cyc_sign + cyc_merkle + cyc_par + cyc_disp + 2 * cyc_kdf;
    double sign_s = cyc_sign / F_CPU;

    /* -------- run */
    kem_gw_t* kg = kem_gw_keygen(KEM_MLKEM512);
    sig_key_t* sk = sig_keygen(sig); size_t pkn; const uint8_t* pk = sig_pk(sk, &pkn);
    quill_params_t pr = { sig, KEM_MLKEM512, n, m, k, 1 };
    quill_gw_t g; quill_gw_init(&g, &pr, kg, pk, pkn);
    memset(&S, 0, sizeof S); S.g = &g; ge_init(&S.ch, loss, burst, seed);
    S.nbatch = np + 1; S.ver_t = malloc(sizeof(double) * S.nbatch);
    for (int b = 0; b < S.nbatch; ++b) S.ver_t[b] = -1;
    g.on_batch = on_batch;
    int* pb = malloc(sizeof(int) * np);                         /* batch of each packet */
    quill_dev_t d; quill_dev_init(&d, &pr, sk, kem_gw_pk(kg), 0x5151, emit, NULL);
    long urgent = 0;
    for (int p = 0; p < np; ++p) {
        S.t = tgen[p];
        pb[p] = (int)d.b;
        if (urg[p]) { urgent++; S.t += sign_s; }                /* AUX frames leave after signing */
        quill_dev_send(&d, pay + (size_t)p * plen, plen, urg[p]);
    }
    S.t = tgen[np - 1] + period + sign_s;
    quill_dev_close(&d);
    quill_gw_finish(&g);

    /* -------- metrics */
    long rx = g.rx_data, ver = g.nr_packets;
    double dsum = 0, dmax = 0; long dn = 0; double usum = 0; long un = 0;
    double* dl = malloc(sizeof(double) * np);
    for (int p = 0; p < np; ++p) {
        double vt = S.ver_t[pb[p]];
        if (vt < 0) continue;
        double dly = vt - tgen[p];
        /* the authenticator of an ordinary batch rides on the next batch's packets once the
           signature is ready; if signing outlasts a packet period the first fragments wait */
        if (!urg[p]) dly += sign_s > period ? sign_s - period : 0;
        dl[dn++] = dly; dsum += dly; if (dly > dmax) dmax = dly;
        if (urg[p]) { usum += dly; un++; }
    }
    /* p95 */
    for (long i = 1; i < dn; ++i) { double x = dl[i]; long j = i - 1; while (j >= 0 && dl[j] > x) { dl[j + 1] = dl[j]; --j; } dl[j + 1] = x; }
    double p95 = dn ? dl[(long)ceil(0.95 * dn) - 1] : 0;
    double dur_h = (tgen[np - 1] + period) / 3600.0;
    long nbat = d.signatures - 1;                               /* minus the INIT signature */
    double cpu_cyc = np * cyc_pkt + nbat * cyc_close;
    double e_cpu = cpu_cyc * E_CYCLE_NJ * 1e-6;                 /* mJ */
    double e_radio = S.air_bytes * E_BYTE_UJ * 1e-3;            /* mJ */
    printf("%s,%s,%d,%d,%d,%d,%.2f,%.0f,%d,%ld,%ld,%.1f,%.1f,%.4f,%.2f,%.2f,%.2f,%.2f,%.3f,%.1f,%.1f,%.1f\n",
           ecg ? "ECG" : "Vitals", sig_info(sig)->name, plen, n, m, k, loss, burst, np, urgent, nbat,
           S.air_bytes / np, S.air_bytes / np - plen, rx ? (double)ver / rx : 0,
           dn ? dsum / dn : 0, p95, dmax, un ? usum / un : 0,
           cpu_cyc / F_CPU / dur_h / 36.0,                      /* CPU duty cycle in percent */
           e_cpu / dur_h, e_radio / dur_h, (e_cpu + e_radio) / dur_h);
    return 0;
}
