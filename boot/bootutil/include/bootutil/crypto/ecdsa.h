/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2022 Arm Limited
 */

/*
 * This module provides a thin abstraction over some of the crypto
 * primitives to make it easier to swap out the used crypto library.
 *
 * At this point, the choices is only: MCUBOOT_USE_PSA_CRYPTO.
 * Since MCUBOOT_USE_PSA_CRYPTO does not yet support all the same
 * abstraction as MCUBOOT_USE_MBED_TLS, the support for PSA Crypto
 * is built on top of mbed TLS, i.e. they must be both defined
 */

#ifndef __BOOTUTIL_CRYPTO_ECDSA_H_
#define __BOOTUTIL_CRYPTO_ECDSA_H_

#include "mcuboot_config/mcuboot_config.h"

#if defined(MCUBOOT_USE_PSA_CRYPTO)
#define MCUBOOT_USE_PSA_OR_MBED_TLS
#endif /* MCUBOOT_USE_PSA_CRYPTO  */

#if (defined(MCUBOOT_USE_PSA_OR_MBED_TLS)) != 1
    #error "One crypto backend must be defined: PSA_CRYPTO"
#endif

#if defined(MCUBOOT_USE_PSA_CRYPTO)
    #include <psa/crypto.h>
    #include <string.h>
#endif /* MCUBOOT_USE_PSA_CRYPTO */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MCUBOOT_USE_PSA_CRYPTO)
typedef struct {
    psa_key_id_t key_id;
} bootutil_ecdsa_context;

static inline void bootutil_ecdsa_init(bootutil_ecdsa_context *ctx)
{
    ctx->key_id = PSA_KEY_ID_NULL;
}

static inline void bootutil_ecdsa_drop(bootutil_ecdsa_context *ctx)
{
    if (ctx->key_id != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(ctx->key_id);
    }
}

#define LEN_OFF (3) /* Offset for the Length field of the second SEQUENCE */
#define VAL_OFF (3) /* Offset for the value field of the BIT STRING */

/* This helper function gets a pointer to the bitstring associated to the publicKey
 * as encoded per RFC 5280. This function assumes that the public key encoding is not
 * bigger than 127 bytes (i.e. usually up until 384 bit curves)
 *
 * \param[in,out] p    Double pointer to a buffer containing the RFC 5280 of the ECDSA public key.
 *                     On output, the pointer is updated to point to the start of the public key
 *                     in BIT STRING form.
 * \param[in]     size Pointer to a buffer containing the size of the public key extracted
 *
 */
static inline void get_public_key_from_rfc5280_encoding(uint8_t **p, size_t *size)
{
    uint8_t *key_start = (*p) + (LEN_OFF + 1 + (*p)[LEN_OFF] + VAL_OFF);
    *p = key_start;
    *size = key_start[-2]-1; /* -2 from VAL_OFF to get the length, -1 to remove the ASN.1 padding byte count */
}

/*
 * Parse a ECDSA public key with format specified in RFC5280 et al.
 *
 * SEQUENCE {
 *    SEQUENCE {
 *        OBJECT idEcPublicKey
 *        OBJECT namedCurve
 *    }
 *    BIT STRING publicKey
 * }
 * 
 * OID for icEcPublicKey is 1.2.840.10045.2.1
 * OIDs for supported curves are as follows:
 *     secp224r1: 1.3.132.0.33
 *     secp256r1 (prime256v1): 1.2.840.10045.3.1.7
 *     secp384r1: 1.3.132.0.34
 */
static int
bootutil_ecdsa_parse_public_key(bootutil_ecdsa_context *ctx, uint8_t **p, uint8_t *end)
{
    psa_key_attributes_t key_attributes = psa_key_attributes_init();
    size_t key_size;

    get_public_key_from_rfc5280_encoding(p, &key_size);

    /* Set attributes and import key */
    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));

    return (int)psa_import_key(&input_key_attr, key_start, key_size, &ctx->key_id);
}

/* This helper function parses a signature as specified in RFC 5480 into a pair
 * (r,s) of contiguous bytes
 *
 * \param[in]  sig      Pointer to a buffer containing the encoded signature
 * \param[in]  slen     Size in bytes of the encoded signature structure
 * \param[out] r_s_pair Buffer containing the (r,s) pair extracted. It's caller
 *                      responsibility to ensure the buffer is big enough to
 *                      hold the parsed (r,s) pair.
 *
 * \return The size in bytes of the parsed signature, i.e. (r,s) pair
 */
static inline size_t parse_signature_from_rfc5480_encoding(const uint8_t *sig,
                                                           size_t slen,
                                                           uint8_t *r_s_pair)
{
    const uint8_t *sig_ptr = NULL;
    /* Move r in place */
    size_t r_len = sig[3];
    if (r_len % 2) {
        sig_ptr = &sig[5];
        r_len--;
    } else {
        sig_ptr = &sig[4];
    }
    memcpy(&r_s_pair[0], sig_ptr, r_len);
    /* Move s in place */
    size_t s_len = sig_ptr[r_len + 1];
    if (s_len % 2) {
        sig_ptr = &sig_ptr[3+r_len];
        s_len--;
    } else {
        sig_ptr = &sig_ptr[2+r_len];
    }
    memcpy(&r_s_pair[r_len], sig_ptr, s_len);
    slen = s_len + r_len; /* Update the length of the signature we're passing */
    return slen;
}

/* PSA Crypto has a dedicated API for ECDSA verification */
static inline int bootutil_ecdsa_verify(const bootutil_rsa_context *ctx,
    uint8_t *hash, size_t hlen, uint8_t *sig, size_t slen)
{
    uint8_t reformatted_signature[96] = {0}; /* Up to P-384 signature sizes */
    slen = parse_signature_from_rfc5480_encoding(sig, slen, reformatted_signature);

    return (int) psa_verify_hash(ctx->key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                 hash, hlen, reformatted_signature, slen);
}
#endif /* MCUBOOT_USE_PSA_CRYPTO */

#ifdef __cplusplus
}
#endif

#endif /* __BOOTUTIL_CRYPTO_ECDSA_H_ */
