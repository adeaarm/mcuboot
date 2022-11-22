/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2021-2022 Arm Limited
 */

#ifndef __BOOTUTIL_CRYPTO_COMMON_H__
#define __BOOTUTIL_CRYPTO_COMMON_H__

#include "mcuboot_config/mcuboot_config.h"

#ifdef MCUBOOT_USE_MBED_TLS
#include "mbedtls/build_info.h"
/* Note: May need to update this in a future 3.x version of Mbed TLS.
 * Extract a private member of the mbedtls context structure.
 */
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
#define MBEDTLS_CONTEXT_MEMBER(X) MBEDTLS_PRIVATE(X)
#else
#define MBEDTLS_CONTEXT_MEMBER(X) X
#endif
#endif /* MCUBOOT_USE_MBED_TLS */

#endif /* __BOOTUTIL_CRYPTO_COMMON_H__ */
