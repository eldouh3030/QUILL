#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#ifdef _WIN32
  #define NOMINMAX            /* windows.h must not define min/max macros */
  #define WIN32_LEAN_AND_MEAN
  #define WOLFSSL_HAVE_MIN    /* MSVC stdlib.h already has min/max macros in C */
  #define WOLFSSL_HAVE_MAX
#endif
/* wolfCrypt configuration shared by the host build and the Cortex-M4 firmware.
   Portable C only (no assembly) so that host and device run the same code. */
#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define NO_ERROR_STRINGS
#define WOLFSSL_NO_SOCK
#define WOLFSSL_USER_IO
#define WOLFSSL_IGNORE_FILE_WARN
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define WOLFSSL_NO_ASM
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT

#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_SP_NO_DYN_STACK

#define HAVE_AESGCM
#define GCM_TABLE_4BIT
#define WOLFSSL_AES_256
#define HAVE_HKDF
#define HAVE_CURVE25519
#define HAVE_ED25519
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#define NO_RSA
#define NO_DSA
#define NO_DH
#define NO_MD4
#define NO_MD5
#define NO_SHA
#define NO_OLD_TLS
#define NO_RC4
#define NO_DES3
#define NO_PSK
#define NO_PWDBASED
#define NO_SESSION_CACHE

/* ML-KEM (FIPS 203) */
#define WOLFSSL_HAVE_KYBER
#define WOLFSSL_WC_KYBER
/* ML-DSA (FIPS 204) */
#define HAVE_DILITHIUM
#define WOLFSSL_WC_DILITHIUM
#define WOLFSSL_DILITHIUM_NO_LARGE_VECTORS
/* LMS/HSS (RFC 8554, SP 800-208) */
#define WOLFSSL_HAVE_LMS
#define WOLFSSL_WC_LMS

#ifdef PQS_FIRMWARE
  #define NO_DEV_RANDOM
  #define NO_ASN_TIME
  #define NO_STDIO_FILESYSTEM
  #define SIZEOF_LONG_LONG 8
  #define SP_WORD_SIZE 32
  #define WOLFSSL_DILITHIUM_SIGN_SMALL_MEM
  #define WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM
  #define WOLFSSL_DILITHIUM_MAKE_KEY_SMALL_MEM
  extern int fw_rng_block(unsigned char* out, unsigned int sz);
  #define CUSTOM_RAND_GENERATE_BLOCK fw_rng_block
  #define CUSTOM_RAND_TYPE unsigned int
  #define XMALLOC_USER
#endif
#endif
