Subset of PQClean (https://github.com/PQClean/PQClean), commit 0586a824fc0d49df0b6b6e9179d8d15d06d0974f
(4 Aug 2026): the `clean` implementations of falcon-padded-512, sphincs-sha2-128s-simple,
sphincs-sha2-128f-simple and ml-dsa-44, and the needed files of `common/`. Each implementation
folder keeps its LICENSE file. Randomness is supplied by `PQCLEAN_randombytes` in `src/crypto.c`.
Note: the SPHINCS+ code is round-3 SPHINCS+ v3.1, which differs in details from FIPS 205 SLH-DSA.
