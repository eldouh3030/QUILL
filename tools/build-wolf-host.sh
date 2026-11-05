#!/bin/sh
# Builds wolfCrypt (portable C) for the host into build/libwolf.a
W=${WOLFSSL_DIR:-../wolfssl}
mkdir -p build/wolf
for f in $W/wolfcrypt/src/*.c; do
  b=$(basename $f .c); [ "$b" = misc ] && continue
  gcc -O2 -c -DWOLFSSL_USER_SETTINGS -Iwolf -I$W $f -o build/wolf/$b.o || exit 1
done
rm -f build/libwolf.a; ar rcs build/libwolf.a build/wolf/*.o
