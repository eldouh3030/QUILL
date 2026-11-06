# QUILL

**Loss-tolerant, post-quantum non-repudiation for medical sensor streams on constrained devices.**

A wearable sensor streams vital signs or ECG over Bluetooth Low Energy. Every packet is
encrypted and authenticated at once with a per-packet AES-256-GCM key, so the gateway can use
the data with no added delay. Packets are grouped in batches of *n*; the device signs the
Merkle root of each batch with a post-quantum signature (ML-DSA-44 by default). The batch
authenticator

    D_b = signature || m parity symbols of the n leaf hashes

is erasure-coded into *n* fragments that travel, encrypted, inside the packets of the next
batch. Any *k* fragments rebuild `D_b`, and any batch with at most *m* lost packets becomes
verifiable: the gateway hashes the packets it received and recovers the missing leaves from the
parity. Each record can later be shown to a third party with a short Merkle path; disclosing
one per-packet key opens exactly that record (key commitment), and nothing else.

The session key comes from a hybrid X25519 + ML-KEM-512 exchange, so recorded traffic stays
confidential unless both are broken (harvest now, decrypt later), and a one-way key chain gives
forward secrecy per batch.

## Contents

| Folder | What it holds |
|---|---|
| `src/` | the protocol (`quill.c`), erasure coding over GF(2^8) (`ecc.c`), crypto wrappers (`crypto.c`), tests, host benchmark, loss simulator, real-data streams |
| `wolf/user_settings.h` | wolfCrypt configuration (portable C, same on host and device) |
| `ext/PQClean/` | the PQClean implementations used (Falcon-512 padded, SPHINCS+-SHA2-128s/f simple, ML-DSA-44), with their licences |
| `mcu/` | Cortex-M4F firmware and the Unicorn-based emulator that counts cycles, stack and heap |
| `formal/` | Tamarin model (`pqs.spthy`), per-lemma proof outputs and the script that proves them |
| `tools/` | figure script, real-data stream runner and summary (20 seeds, 95% CI), merge of the emulator results, host wolfCrypt build script |
| `data/` | MIT-BIH record 100 and MIMIC numerics used by the stream experiments (see `data/README.md`) |
| `results/` | every CSV and log the paper reports |

## Build and run (Windows, Visual Studio 2022)

1. *File → Open → Folder…* and choose this folder. Visual Studio reads `CMakePresets.json`.
2. Select the **Release (optimised)** configuration, then *Build → Build All*.
   wolfSSL v5.7.6-stable is downloaded at configure time (it is GPLv3 and therefore not stored here).
3. In a terminal in this folder:

```
out\build\release\tests.exe
out\build\release\hostbench.exe 300 2 | Out-File -Encoding ascii results-laptop\primitives.csv
```

## Build and run (Linux)

```
cmake --preset release && cmake --build out/build/release -j
./out/build/release/tests
./out/build/release/hostbench 300 2 > results-laptop/primitives.csv
./out/build/release/sim validate        > results/validate.csv
./out/build/release/sim optimise 16     > results/optimise-16.csv
./out/build/release/sim optimise 96     > results/optimise-96.csv
./out/build/release/sim compare 16      > results/compare-16.csv
./out/build/release/sim fair 16         > results/fair-16.csv
./out/build/release/sim adaptive 16     > results/adaptive-16.csv
python3 tools/merge-mcu.py              # results/mcu-*.csv -> results/mcu-all.csv
BIN=out/build/release ./tools/run-streams.sh > results/streams-runs.csv
python3 tools/summarise-streams.py results/streams-runs.csv > results/streams.csv
python3 tools/make-figures.py fig/
```

The emulated device measurements are described in `mcu/README.md`; the formal model in
`formal/README.md`.

## Parameters

| Symbol | Meaning | Default |
|---|---|---|
| n | packets per batch (one signature) | 32 (vital signs), 64 (ECG) |
| m | lost packets a batch tolerates (leaf parity symbols) | tuned to the channel |
| k | fragments needed to rebuild the authenticator (of n) | tuned to the channel |

`sim optimise` picks *m* and *k* that minimise the bytes per packet while a batch stays
verifiable with probability 0.99 under a Gilbert–Elliott loss model.

*m* and *k* may change from batch to batch: every DATA header (14 bytes) carries *n*, *m* and *k*
of the batch its fragment belongs to. In the adaptive mode (`quill_dev_set_mk`, `sim adaptive`)
the gateway reports the lost frames and loss runs of each batch, and the device picks (*m*, *k*)
from a 55-entry table computed with the exact model (target 0.995).

The coding of the signature together with parity of the packet hashes follows Pannetrat and
Molva (NDSS 2003); QUILL adds the Merkle-root evidence, key commitments, encrypted fragments,
immediate per-packet authenticity, the hybrid session and the adaptive parameters.

## Licence

MIT for the code in this repository (see `LICENSE`). PQClean files keep their own licences
(public domain / CC0, MIT for Falcon). wolfSSL is GPLv3 and is fetched separately.
