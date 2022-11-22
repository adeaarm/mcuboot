/*
 * This module provides a thin abstraction over some of the crypto
 * primitives to make it easier to swap out the used crypto library.
 *
 * At this point, the choices are: MCUBOOT_USE_MBED_TLS, MCUBOOT_USE_TINYCRYPT
 * or MCUBOOT_USE_PSA_CRYPTO. Since MCUBOOT_USE_PSA_CRYPTO does not yet
 * support all the same abstraction as MCUBOOT_USE_MBED_TLS, the support for
 * PSA Crypto is built on top of mbed TLS, i.e. they must be both defined
 */

#ifndef __BOOTUTIL_CRYPTO_AES_CTR_H_
#define __BOOTUTIL_CRYPTO_AES_CTR_H_

#include <string.h>

#include "mcuboot_config/mcuboot_config.h"

#if defined(MCUBOOT_USE_PSA_CRYPTO) || defined(MCUBOOT_USE_MBED_TLS)
#define MCUBOOT_USE_PSA_OR_MBED_TLS
#endif /* MCUBOOT_USE_PSA_CRYPTO || MCUBOOT_USE_MBED_TLS */

#if (defined(MCUBOOT_USE_PSA_OR_MBED_TLS) + \
     defined(MCUBOOT_USE_TINYCRYPT) ) != 1
    #error "One crypto backend must be defined: either MBED_TLS/TINYCRYPT/PSA_CRYPTO"
#endif

#if defined(MCUBOOT_USE_PSA_CRYPTO)
    #include <psa/crypto.h>
    #include "bootutil/enc_key_public.h"
    #define BOOTUTIL_CRYPTO_AES_CTR_KEY_SIZE BOOT_ENC_KEY_SIZE
#elif defined(MCUBOOT_USE_MBED_TLS)
    #include <mbedtls/aes.h>
    #include "bootutil/enc_key_public.h"
    #define BOOTUTIL_CRYPTO_AES_CTR_KEY_SIZE BOOT_ENC_KEY_SIZE
    #define BOOTUTIL_CRYPTO_AES_CTR_BLOCK_SIZE (16)
#endif /* MCUBOOT_USE_MBED_TLS */

#if defined(MCUBOOT_USE_TINYCRYPT)
    #if defined(MCUBOOT_AES_256)
        #error "Cannot use AES-256 for encryption with Tinycrypt library."
    #endif
    #include <string.h>
    #include <tinycrypt/aes.h>
    #include <tinycrypt/ctr_mode.h>
    #include <tinycrypt/constants.h>
    #define BOOTUTIL_CRYPTO_AES_CTR_KEY_SIZE TC_AES_KEY_SIZE
    #define BOOTUTIL_CRYPTO_AES_CTR_BLOCK_SIZE TC_AES_BLOCK_SIZE
#endif /* MCUBOOT_USE_TINYCRYPT */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MCUBOOT_USE_PSA_CRYPTO)
typedef struct {
    psa_cipher_operation_t op;
    psa_key_id_t key_id;
} bootutil_aes_ctr_context;

static inline void bootutil_aes_ctr_init(bootutil_aes_ctr_context *ctx)
{
    ctx->op = psa_cipher_operation_init();
    ctx->key_id = PSA_KEY_ID_NULL;
}

static inline void bootutil_aes_ctr_drop(bootutil_aes_ctr_context *ctx)
{
    (void)psa_cipher_abort(&(ctx->op));
    if (ctx->key_id != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(ctx->key_id);
    }
}

static inline int bootutil_aes_ctr_set_key(bootutil_aes_ctr_context *ctx, const uint8_t *k)
{
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    psa_key_attributes_t key_attributes = psa_key_attributes_init();
    psa_key_usage_t usage = (PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);

    /* Setup the key policy */
    psa_set_key_usage_flags(&key_attributes, usage);
    psa_set_key_algorithm(&key_attributes, PSA_ALG_CTR);
    psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);

    /* Import a key */
    status = psa_import_key(&key_attributes, k, BOOTUTIL_CRYPTO_AES_CTR_KEY_SIZE,
                            &(ctx->key_id));
    if (status != PSA_SUCCESS) {
        return (int)status;
    }

    /* Setup the object always as encryption for CTR*/
    return (int)psa_cipher_encrypt_setup(&(ctx->op), ctx->key_id, PSA_ALG_CTR);
}

static inline int bootutil_aes_ctr_encrypt(bootutil_aes_ctr_context *ctx, uint8_t *counter, const uint8_t *m, uint32_t mlen, size_t blk_off, uint8_t *c)
{
    (void)counter; (void)blk_off; /* These are handled by the API */
    size_t output_length = 0; size_t clen = mlen;
    return (int)psa_cipher_update(&(ctx->op), m, mlen, c, clen, &output_length);
}

static inline int bootutil_aes_ctr_decrypt(bootutil_aes_ctr_context *ctx, uint8_t *counter, const uint8_t *c, uint32_t clen, size_t blk_off, uint8_t *m)
{
    (void)counter; (void)blk_off; /* These are handled by the API */
    size_t output_length = 0; size_t mlen = clen;
    return (int)psa_cipher_update(&(ctx->op), c, clen, m, mlen, &output_length);
}
#elif defined(MCUBOOT_USE_MBED_TLS)
typedef mbedtls_aes_context bootutil_aes_ctr_context;
static inline void bootutil_aes_ctr_init(bootutil_aes_ctr_context *ctx)
{
    (void)mbedtls_aes_init(ctx);
}

static inline void bootutil_aes_ctr_drop(bootutil_aes_ctr_context *ctx)
{
    /* XXX: config defines MBEDTLS_PLATFORM_NO_STD_FUNCTIONS so no need to free */
    /* (void)mbedtls_aes_free(ctx); */
    (void)ctx;
}

static inline int bootutil_aes_ctr_set_key(bootutil_aes_ctr_context *ctx, const uint8_t *k)
{
    return mbedtls_aes_setkey_enc(ctx, k, BOOTUTIL_CRYPTO_AES_CTR_KEY_SIZE * 8);
}

static inline int bootutil_aes_ctr_encrypt(bootutil_aes_ctr_context *ctx, uint8_t *counter, const uint8_t *m, uint32_t mlen, size_t blk_off, uint8_t *c)
{
    uint8_t stream_block[BOOTUTIL_CRYPTO_AES_CTR_BLOCK_SIZE];
    return mbedtls_aes_crypt_ctr(ctx, mlen, &blk_off, counter, stream_block, m, c);
}

static inline int bootutil_aes_ctr_decrypt(bootutil_aes_ctr_context *ctx, uint8_t *counter, const uint8_t *c, uint32_t clen, size_t blk_off, uint8_t *m)
{
    uint8_t stream_block[BOOTUTIL_CRYPTO_AES_CTR_BLOCK_SIZE];
    return mbedtls_aes_crypt_ctr(ctx, clen, &blk_off, counter, stream_block, c, m);
}
#endif /* MCUBOOT_USE_MBED_TLS */

#if defined(MCUBOOT_USE_TINYCRYPT)
typedef struct tc_aes_key_sched_struct bootutil_aes_ctr_context;
static inline void bootutil_aes_ctr_init(bootutil_aes_ctr_context *ctx)
{
    (void)ctx;
}

static inline void bootutil_aes_ctr_drop(bootutil_aes_ctr_context *ctx)
{
    (void)ctx;
}

static inline int bootutil_aes_ctr_set_key(bootutil_aes_ctr_context *ctx, const uint8_t *k)
{
    int rc;
    rc = tc_aes128_set_encrypt_key(ctx, k);
    if (rc != TC_CRYPTO_SUCCESS) {
        return -1;
    }
    return 0;
}

static int _bootutil_aes_ctr_crypt(bootutil_aes_ctr_context *ctx, uint8_t *counter, const uint8_t *in, uint32_t inlen, uint32_t blk_off, uint8_t *out)
{
    int rc;
    rc = tc_ctr_mode(out, inlen, in, inlen, counter, &blk_off, ctx);
    if (rc != TC_CRYPTO_SUCCESS) {
        return -1;
    }
    return 0;
}

static inline int bootutil_aes_ctr_encrypt(bootutil_aes_ctr_context *ctx, uint8_t *counter, const uint8_t *m, uint32_t mlen, uint32_t blk_off, uint8_t *c)
{
    return _bootutil_aes_ctr_crypt(ctx, counter, m, mlen, blk_off, c);
}

static inline int bootutil_aes_ctr_decrypt(bootutil_aes_ctr_context *ctx, uint8_t *counter, const uint8_t *c, uint32_t clen, uint32_t blk_off, uint8_t *m)
{
    return _bootutil_aes_ctr_crypt(ctx, counter, c, clen, blk_off, m);
}
#endif /* MCUBOOT_USE_TINYCRYPT */

#ifdef __cplusplus
}
#endif

#endif /* __BOOTUTIL_CRYPTO_AES_CTR_H_ */
