/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (C) 2022 Arm Limited
 *
 * Original license:
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <string.h>

#include "mcuboot_config/mcuboot_config.h"

#ifdef MCUBOOT_SIGN_ECDSA
#include "bootutil_priv.h"
#include "bootutil/sign_key.h"
#include "bootutil/fault_injection_hardening.h"

#include "bootutil/crypto/ecdsa.h"

static fih_int
bootutil_cmp_ecdsa_sig(bootutil_rsa_context *ctx, uint8_t *hash, uint32_t hlen,
  uint8_t *sig, size_t slen)
{
    int rc = 0;
    fih_int fih_rc = FIH_FAILURE;

    /* PSA Crypto APIs allow the verification in a single call */
    rc = bootutil_ecdsa_verify(ctx, hash, hlen, sig, slen);

    fih_rc = fih_int_encode(rc);

    FIH_RET(fih_rc);
}

fih_int
bootutil_verify_sig(uint8_t *hash, uint32_t hlen, uint8_t *sig, size_t slen,
  uint8_t key_id)
{
    int rc = 0;
    fih_int fih_rc = FIH_FAILURE;
    uint8_t *cp;
    uint8_t *end;
    bootutil_ecdsa_context ctx;

    bootutil_ecdsa_init(&ctx);

    cp = (uint8_t *)bootutil_keys[key_id].key;
    end = cp + *bootutil_keys[key_id].len;

    /* The key used for signature verification is a public ECDSA key */
    rc = bootutil_ecdsa_parse_public_key(&ctx, &cp, end);
    if (rc) {
        goto out;
    }

    FIH_CALL(bootutil_cmp_ecdsa_sig, fih_rc, &ctx, hash, hlen, sig, slen);

out:
    bootutil_ecdsa_drop(&ctx);

    if (rc) {
        fih_rc = fih_int_encode(rc);
    }

    FIH_RET(fih_rc);
}
#endif /* MCUBOOT_SIGN_ECDSA */
