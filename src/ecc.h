/* Erasure coding over GF(2^8) with Cauchy matrices (MDS: any square
   submatrix of a Cauchy matrix is invertible).

   Two uses in the protocol:
   1. dispersal: a block D is split into k data symbols and expanded to
      nf >= k fragments; any k fragments rebuild D.
   2. leaf parity: from n leaf hashes the sender computes m parity symbols;
      a receiver that already holds n - e leaves (it hashes the packets it
      received) rebuilds the e <= m missing leaves from e parity symbols. */
#ifndef QUILL_ECC_H
#define QUILL_ECC_H
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ECC_MAX 255

void gf_init(void);

/* parity[r] = sum_j C[r][j] * data[j], C[r][j] = 1 / (x_r + y_j),
   x_r = r, y_j = np + j. Symbols are `len` bytes each.
   Requires np + nd <= 256. */
void ecc_parity(const uint8_t* const* data, int nd, uint8_t* const* parity, int np, size_t len);

/* Rebuild the data symbols listed in `miss` (count ne) from the known data
   symbols (data[j] valid when j is not in miss) and parity symbols with
   indices prow[0..ne-1]. data[miss[i]] is written. Returns 0 on success. */
int ecc_recover(uint8_t* const* data, int nd, const int* miss, int ne,
                const uint8_t* const* parity, const int* prow, int np, size_t len);

/* Dispersal of a byte block D into nf fragments of size F = ceil(Dn / k).
   frag must hold nf * F bytes. Fragments 0..k-1 are systematic. */
size_t disp_frag_size(size_t Dn, int k);
void   disp_encode(const uint8_t* D, size_t Dn, int k, int nf, uint8_t* frag);
/* have[j] != 0 when fragment j (at frag + j*F) is present; needs >= k.
   Writes D (Dn bytes). Returns 0 on success. */
int    disp_decode(const uint8_t* frag, const uint8_t* have, int k, int nf, size_t Dn, uint8_t* D);

#ifdef __cplusplus
}
#endif
#endif
