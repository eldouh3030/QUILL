# Host build (gateway side, simulations, tests). Needs build/libwolf.a (tools/build-wolf-host.sh)
W ?= ../wolfssl
CFLAGS = -O2 -Wall -Wno-unused-function -DWOLFSSL_USER_SETTINGS -Iwolf -I$(W) -Isrc
PQC = ext/PQClean
PQSRC = $(wildcard $(PQC)/crypto_sign/falcon-padded-512/clean/*.c) \
        $(wildcard $(PQC)/crypto_sign/sphincs-sha2-128s-simple/clean/*.c) \
        $(wildcard $(PQC)/crypto_sign/sphincs-sha2-128f-simple/clean/*.c) \
        $(wildcard $(PQC)/crypto_sign/ml-dsa-44/clean/*.c) \
        $(PQC)/common/fips202.c $(PQC)/common/sha2.c $(PQC)/common/sp800-185.c
CORE = src/crypto.c src/ecc.c src/quill.c
all: build/tests
build/libpqc.a: $(PQSRC)
	mkdir -p build/pqc; for f in $(PQSRC); do d=$$(basename $$(dirname $$(dirname $$f))); gcc -O2 -c -I$(PQC)/common $$f -o build/pqc/$$d-$$(basename $$f .c).o || exit 1; done; rm -f $@; ar rcs $@ build/pqc/*.o
build/%: src/%.c $(CORE) src/*.h build/libpqc.a
	gcc $(CFLAGS) $< $(CORE) build/libwolf.a build/libpqc.a -lm -o $@
