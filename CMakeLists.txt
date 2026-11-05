cmake_minimum_required(VERSION 3.16)
project(pq-iomt-stream C)

# wolfSSL (wolfCrypt only, portable C) and PQClean are fetched at the versions
# used in the paper. Set WOLFSSL_DIR / PQCLEAN_DIR to use local checkouts.
include(FetchContent)
if(NOT WOLFSSL_DIR)
  FetchContent_Declare(wolfssl URL https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.7.6-stable.zip
                        DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  FetchContent_GetProperties(wolfssl)
  if(NOT wolfssl_POPULATED)
    FetchContent_Populate(wolfssl)
  endif()
  set(WOLFSSL_DIR ${wolfssl_SOURCE_DIR})
endif()
if(NOT PQCLEAN_DIR)
  set(PQCLEAN_DIR ${CMAKE_SOURCE_DIR}/ext/PQClean)
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(WC ${WOLFSSL_DIR}/wolfcrypt/src)
add_library(wolfcrypt STATIC
  ${WC}/aes.c ${WC}/sha256.c ${WC}/sha512.c ${WC}/sha3.c ${WC}/hmac.c ${WC}/hash.c ${WC}/random.c
  ${WC}/memory.c ${WC}/logging.c ${WC}/error.c ${WC}/wc_port.c ${WC}/kdf.c ${WC}/wc_encrypt.c
  ${WC}/curve25519.c ${WC}/fe_operations.c ${WC}/ge_operations.c ${WC}/ed25519.c
  ${WC}/wc_kyber.c ${WC}/wc_kyber_poly.c ${WC}/dilithium.c ${WC}/wc_lms.c ${WC}/wc_lms_impl.c
  ${WC}/asn.c ${WC}/coding.c ${WC}/wolfmath.c ${WC}/sp_int.c)
target_include_directories(wolfcrypt PUBLIC ${CMAKE_SOURCE_DIR}/wolf ${WOLFSSL_DIR})
target_compile_definitions(wolfcrypt PUBLIC WOLFSSL_USER_SETTINGS)

file(GLOB PQ_FALCON  ${PQCLEAN_DIR}/crypto_sign/falcon-padded-512/clean/*.c)
file(GLOB PQ_SPX_S   ${PQCLEAN_DIR}/crypto_sign/sphincs-sha2-128s-simple/clean/*.c)
file(GLOB PQ_SPX_F   ${PQCLEAN_DIR}/crypto_sign/sphincs-sha2-128f-simple/clean/*.c)
file(GLOB PQ_MLDSA   ${PQCLEAN_DIR}/crypto_sign/ml-dsa-44/clean/*.c)
foreach(part falcon spx_s spx_f mldsa)
  string(TOUPPER ${part} P)
  add_library(pq_${part} STATIC ${PQ_${P}})
  target_include_directories(pq_${part} PRIVATE ${PQCLEAN_DIR}/common)
endforeach()
add_library(pq_common STATIC ${PQCLEAN_DIR}/common/fips202.c ${PQCLEAN_DIR}/common/sha2.c ${PQCLEAN_DIR}/common/sp800-185.c)

add_library(quill STATIC src/crypto.c src/ecc.c src/quill.c)
target_include_directories(quill PUBLIC src)
target_link_libraries(quill PUBLIC wolfcrypt pq_falcon pq_spx_s pq_spx_f pq_mldsa pq_common)
if(NOT MSVC)
  target_link_libraries(quill PUBLIC m)
endif()

foreach(t tests hostbench sim stream)
  add_executable(${t} src/${t}.c)
  target_link_libraries(${t} quill)
endforeach()
if(WIN32)
  target_link_libraries(wolfcrypt PUBLIC advapi32)
endif()
