# Device measurements (emulated ARM Cortex-M4F)

The device side of QUILL is the same C source as the host build (`../src/`), compiled for
`thumbv7em-none-eabihf` and executed instruction by instruction in Unicorn. A hook counts
instructions and assigns cycles from the Cortex-M4 Technical Reference Manual (zero wait states).
Stack depth is measured by painting the stack before each call; heap is the peak in-use size of a
free-list allocator (`fwlib.c`). Cycle counts are converted to time at 64 MHz (nRF52840-class SoC).

External check: our ML-DSA-44 signing mean (12.4 M cycles, 300 runs) is close to wolfSSL's
published STM32F4 figure for the same library (60.3 ms at 168 MHz = 10.1 M cycles), and the
ML-KEM-512 encapsulation (inside the 4.26 M-cycle hybrid with X25519) is consistent with it too.

## Toolchain used

- clang 18 and ld.lld (target `thumbv7em-none-eabihf`, `-O2`, hard float)
- Unicorn 2.1.3 built from source (`cmake -DUNICORN_ARCH=arm`)
- wolfSSL 5.7.6-stable (wolfCrypt only, `../wolf/user_settings.h` with `PQS_FIRMWARE`)
- compiler-rt builtins: `aeabi_memset.S`, `aeabi_uldivmod.S`, `udivmoddi4.c` compiled for the same
  target into `rt/` (`rt_aeabi_memset_S.o`, `rt_aeabi_uldivmod_S.o`, `rt_udivmoddi4_c.o`)

## Build and run

```
WOLFSSL_DIR=/path/to/wolfssl UNICORN_DIR=/path/to/unicorn ./build.sh
./run fw.bin syms.txt plan-full.txt       ../results/mcu-emulated.csv
./run fw.bin syms.txt plan-components.txt ../results/mcu-components.csv
./run fw.bin syms.txt plan-extra.txt      ../results/mcu-extra.csv
./run fw.bin syms.txt plan-protocol.txt   ../results/mcu-protocol.csv
```

Plan lines are `<function> <payload> <reps> <sig> <n> <m> <k>`; `reps = 0` runs a preparation
step without measuring. Signature ids: 0 ML-DSA-44, 1 Falcon-512, 2 SPHINCS+-128s,
3 SPHINCS+-128f, 4 LMS/HSS, 5 Ed25519, 6 ML-DSA-44 (PQClean).

`results/mcu-all.csv` merges the four files (protocol rows from the final code replace the
earlier ones) and is what `src/stream.c` reads.
