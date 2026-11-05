#!/bin/sh
# Builds the Cortex-M4F firmware (clang 18, ld.lld) and the Unicorn harness.
set -e
W=${WOLFSSL_DIR:-../../wolfssl}; P=../ext/PQClean; U=${UNICORN_DIR:-../../unicorn}
CF="--target=thumbv7em-none-eabihf -mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -O2 -ffreestanding -fno-builtin-printf -ffunction-sections -fdata-sections -nostdlibinc -isystem inc -isystem /usr/lib/llvm-18/lib/clang/18/include -I../wolf -I$W -I../src -DWOLFSSL_USER_SETTINGS -DPQS_FIRMWARE -Wno-everything"
mkdir -p obj
for f in aes sha256 sha512 sha3 hmac hash random memory logging error wc_port kdf \
         curve25519 fe_operations ge_operations ed25519 wc_kyber wc_kyber_poly dilithium wc_lms wc_lms_impl; do
  clang $CF -c $W/wolfcrypt/src/$f.c -o obj/w-$f.o
done
for d in falcon-padded-512 sphincs-sha2-128s-simple sphincs-sha2-128f-simple ml-dsa-44; do
  for f in $P/crypto_sign/$d/clean/*.c; do clang $CF -I$P/common -c $f -o obj/p-$d-$(basename $f .c).o; done
done
for f in fips202 sha2 sp800-185; do clang $CF -I$P/common -c $P/common/$f.c -o obj/p-common-$f.o; done
for f in crypto ecc quill; do clang $CF -c ../src/$f.c -o obj/s-$f.o; done
clang $CF -c bench.c -o obj/bench.o; clang $CF -c fwlib.c -o obj/fwlib.o
U_SYMS=$(grep -o "^void \(op_[a-z0-9_]*\|prep_[a-z_]*\|setup\|heap_reset\)" bench.c | awk '{printf "-u %s ", $2}')
ld.lld -T link.ld --gc-sections $U_SYMS -u g_len -u g_status -u g_n -u g_m -u g_k -u g_sig obj/*.o rt/*.o -o fw.elf
llvm-objcopy -O binary fw.elf fw.bin
llvm-nm fw.elf | awk 'NF==3 {print $3, $1}' > syms.txt
gcc -O2 -I$U/include run.c -o run $U/build/libunicorn.a -lpthread -lm
