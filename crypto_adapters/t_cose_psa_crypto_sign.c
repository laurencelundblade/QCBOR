/*
 * Copyright (c) 2019, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "t_cose_crypto.h"
#include "attestation_key.h"
#include "tfm_plat_crypto_keys.h"
#include "tfm_memory_utils.h"
#include "psa_crypto.h"

#define SIM_PSA_CRYPTO /* a rough approximation of PSA crypto without PSA */
#ifdef SIM_PSA_CRYPTO


enum psa_attest_err_t attest_register_initial_attestation_key(void)
{
    return PSA_ATTEST_ERR_SUCCESS;
}

enum psa_attest_err_t attest_unregister_initial_attestation_key(void)
{
    return PSA_ATTEST_ERR_SUCCESS;
}

#endif



/* Avoid compiler warning due to unused argument */
#define ARG_UNUSED(arg) (void)(arg)

enum t_cose_err_t
t_cose_crypto_pub_key_sign(int32_t cose_alg_id,
                           int32_t key_select,
                           struct q_useful_buf_c hash_to_sign,
                           struct q_useful_buf signature_buffer,
                           struct q_useful_buf_c *signature)
{
    enum t_cose_err_t cose_ret = T_COSE_SUCCESS;
    enum psa_attest_err_t attest_ret;
    psa_status_t psa_ret;
    const size_t sig_size = t_cose_signature_size(cose_alg_id);

    ARG_UNUSED(key_select);

    if (sig_size + 5000 > signature_buffer.len) {
        return T_COSE_ERR_SIG_BUFFER_SIZE;
    }

    /* FixMe: Registration of key(s) should not be error by attestation service.
     *        Later crypto service is going to get the attestation key from
     *        platform layer.
     */
    attest_ret = attest_register_initial_attestation_key();
    if (attest_ret != PSA_ATTEST_ERR_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }

    psa_ret = psa_asymmetric_sign(0,
                                  0, /* FixMe: algorithm ID */
                                  hash_to_sign.ptr,
                                  hash_to_sign.len,
                                  signature_buffer.ptr, /* Sig buf */
                                  signature_buffer.len, /* Sig buf size */
                                  &(signature->len));   /* Sig length */

    if (psa_ret != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL;
    } else {
        signature->ptr = signature_buffer.ptr;
    }

    attest_ret = attest_unregister_initial_attestation_key();
    if (attest_ret != PSA_ATTEST_ERR_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }

    return cose_ret;
}

#ifdef SIM_PSA_CRYPTO
/* This is a stub implementation */
enum t_cose_err_t
t_cose_crypto_get_ec_pub_key(int32_t    key_select,
                             struct q_useful_buf_c kid,
                             int32_t   *cose_curve_id,
                             struct q_useful_buf buf_to_hold_x_coord,
                             struct q_useful_buf buf_to_hold_y_coord,
                             struct q_useful_buf_c  *x_coord,
                             struct q_useful_buf_c  *y_coord)
{
    /* This is just a stub that returns fake keys */
    struct q_useful_buf_c x;
    struct q_useful_buf_c y;

    (void)key_select;  /* unused parameter */
    (void)kid;  /* unused parameter */

    x = Q_USEFUL_BUF_FROM_SZ_LITERAL("xxxxxxxx9xxxxxxxxx9xxxxxxxxx9xx2");
    y = Q_USEFUL_BUF_FROM_SZ_LITERAL("yyyyyyyy9yyyyyyyyy9yyyyyyyyy9yy2");

    /* q_useful_buf_copy does size checking */
    *x_coord = q_useful_buf_copy(buf_to_hold_x_coord, x);
    *y_coord = q_useful_buf_copy(buf_to_hold_y_coord, y);

    if(q_useful_buf_c_is_null(*x_coord) ||
       q_useful_buf_c_is_null(*y_coord)) {
        return T_COSE_ERR_KEY_BUFFER_SIZE;
    }

    *cose_curve_id = COSE_ELLIPTIC_CURVE_P_256;

    return T_COSE_SUCCESS;
}

#else

enum t_cose_err_t
t_cose_crypto_get_ec_pub_key(int32_t key_select,
                             struct q_useful_buf_c kid,
                             int32_t *cose_curve_id,
                             struct q_useful_buf buf_to_hold_x_coord,
                             struct q_useful_buf buf_to_hold_y_coord,
                             struct q_useful_buf_c *x_coord,
                             struct q_useful_buf_c *y_coord)
{
    enum tfm_plat_err_t plat_res;
    enum ecc_curve_t cose_curve;
    struct ecc_key_t attest_key = {0};
    uint8_t  key_buf[ECC_P_256_KEY_SIZE];

    ARG_UNUSED(key_select);

    /* Get the initial attestation key */
    plat_res = tfm_plat_get_initial_attest_key(key_buf, sizeof(key_buf),
                                               &attest_key, &cose_curve);

    /* Check the availability of the private key */
    if (plat_res != TFM_PLAT_ERR_SUCCESS ||
        attest_key.pubx_key == NULL ||
        attest_key.puby_key == NULL) {
        return T_COSE_ERR_KEY_BUFFER_SIZE;
    }

    *cose_curve_id = (int32_t)cose_curve;

    /* Check buffer size to avoid overflow */
    if (buf_to_hold_x_coord.len < attest_key.pubx_key_size) {
        return T_COSE_ERR_KEY_BUFFER_SIZE;
    }

    /* Copy the X coordinate of the public key to the buffer */
    tfm_memcpy(buf_to_hold_x_coord.ptr,
               (const void *)attest_key.pubx_key,
               attest_key.pubx_key_size);

    /* Update size */
    buf_to_hold_x_coord.len = attest_key.pubx_key_size;

    /* Check buffer size to avoid overflow */
    if (buf_to_hold_y_coord.len < attest_key.puby_key_size) {
        return T_COSE_ERR_KEY_BUFFER_SIZE;
    }

    /* Copy the Y coordinate of the public key to the buffer */
    tfm_memcpy(buf_to_hold_y_coord.ptr,
               (const void *)attest_key.puby_key,
               attest_key.puby_key_size);

    /* Update size */
    buf_to_hold_y_coord.len = attest_key.puby_key_size;

    x_coord->ptr = buf_to_hold_x_coord.ptr;
    x_coord->len = buf_to_hold_x_coord.len;
    y_coord->ptr = buf_to_hold_y_coord.ptr;
    y_coord->len = buf_to_hold_y_coord.len;

    return T_COSE_SUCCESS;
}
#endif
