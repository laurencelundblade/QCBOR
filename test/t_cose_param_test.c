/*
 *  t_cose_param_test.c
 *
 * Copyright 2022-2023, Laurence Lundblade
 * Created by Laurence Lundblade on 9/20/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "t_cose_param_test.h"

#include "t_cose/t_cose_parameters.h"

#include <limits.h>
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose/q_useful_buf.h"

#include "t_cose/t_cose_standard_constants.h"


/* Param with label 44 carries a single float. This test
 * encodes the value of 3.14 and expects that when decoding
 */
static enum t_cose_err_t
encode_44(const struct t_cose_parameter  *param,
          QCBOREncodeContext                *qcbor_encoder)
{
    QCBOREncode_AddDoubleToMapN(qcbor_encoder, param->label,  3.14);
    return T_COSE_SUCCESS;
}

static enum t_cose_err_t
decode_44(void                    *callback_context,
          QCBORDecodeContext      *qcbor_decoder,
          struct t_cose_parameter *p)
{
    double  d;

    (void)callback_context;

    QCBORDecode_GetDouble(qcbor_decoder, &d);
    /* Stuff the double into the little buf because that's what we're
     * doing for label 44 floats.
     */
    memcpy(p->value.special_decode.value.little_buf, &d, sizeof(d));
    return T_COSE_SUCCESS;
}

static int32_t
check_44(struct t_cose_parameter *param)
{
    if(param->label != 44) {
        return 1;
    }

    /* Have to have some comparision function in the test case. */
    double d;
    memcpy(&d, param->value.special_decode.value.little_buf, sizeof(d));

    if(d != 3.14) {
        return 3;
    }

    return 0;
}


static int32_t
check_alg_id(struct t_cose_parameter *param)
{
    if(param->label != T_COSE_HEADER_PARAM_ALG) {
        return 1;
    }

    if(param->value_type != T_COSE_PARAMETER_TYPE_INT64) {
        return 2;
    }

    if(param->value.int64 != T_COSE_ALGORITHM_ES256) {
        return 3;
    }

    if(!param->in_protected) {
        return 6;
    }

    if(param->critical) {
        return 7;
    }

    return 0;
}


static int32_t
check_int_content_id(struct t_cose_parameter *param)
{
    if(param->label != T_COSE_HEADER_PARAM_CONTENT_TYPE) {
        return 1;
    }

    if(param->value_type != T_COSE_PARAMETER_TYPE_INT64) {
        return 2;
    }

    if(param->value.int64 != 42) {
        return 3;
    }

    if(param->in_protected) {
        return 6;
    }

    if(param->critical) {
        return 7;
    }

    return 0;
}


static int32_t
check_text_content_id(struct t_cose_parameter *param)
{
    if(param->label != T_COSE_HEADER_PARAM_CONTENT_TYPE) {
        return 1;
    }

    if(param->value_type != T_COSE_PARAMETER_TYPE_TEXT_STRING) {
        return 2;
    }

    if(q_useful_buf_compare(param->value.string, Q_USEFUL_BUF_FROM_SZ_LITERAL("text/plain"))) {
        return 3;
    }

    if(param->in_protected) {
        return 6;
    }

    if(param->critical) {
        return 7;
    }

    return 0;
}


static int32_t
check_kid(struct t_cose_parameter *param)
{
    if(param->label != T_COSE_HEADER_PARAM_KID) {
        return 1;
    }

    if(param->value_type != T_COSE_PARAMETER_TYPE_BYTE_STRING) {
        return 2;
    }

    if(q_useful_buf_compare(param->value.string, Q_USEFUL_BUF_FROM_SZ_LITERAL("this-is-a-kid"))) {
        return 3;
    }

    if(param->in_protected) {
        return 6;
    }

    if(param->critical) {
        return 7;
    }

    return 0;
}


static int32_t
check_iv(struct t_cose_parameter *param)
{
    if(param->label != T_COSE_HEADER_PARAM_IV) {
        return 1;
    }

    if(param->value_type != T_COSE_PARAMETER_TYPE_BYTE_STRING) {
        return 2;
    }

    if(q_useful_buf_compare(param->value.string, Q_USEFUL_BUF_FROM_SZ_LITERAL("iviviviv"))) {
        return 3;
    }

    if(param->in_protected) {
        return 6;
    }

    if(param->critical) {
        return 7;
    }

    return 0;
}


static int32_t
check_partial_iv(struct t_cose_parameter *param)
{
    if(param->label != T_COSE_HEADER_PARAM_PARTIAL_IV) {
        return 1;
    }

    if(param->value_type != T_COSE_PARAMETER_TYPE_BYTE_STRING) {
        return 2;
    }

    if(q_useful_buf_compare(param->value.string, Q_USEFUL_BUF_FROM_SZ_LITERAL("piv"))) {
        return 3;
    }

    if(param->in_protected) {
        return 6;
    }

    if(param->critical) {
        return 7;
    }

    return 0;
}


static int32_t
check_empty(struct t_cose_parameter *param)
{
    /* An error if param is not NULL */
    return param == NULL ? 0 : 1;
}


static enum t_cose_err_t
param_encoder(const struct t_cose_parameter  *param,
              QCBOREncodeContext             *cbor_encoder)
{
    switch(param->label) {
        case 44:
            return encode_44(param, cbor_encoder);

        case 55:
            /* The point of this one is to fail */
            return T_COSE_ERR_FAIL;

        case 66:
            /* Intentionally don't close the map */
            QCBOREncode_OpenMapInMapN(cbor_encoder, param->label);
            return T_COSE_SUCCESS;

        default:
            return T_COSE_ERR_FAIL;
    }
}


static enum t_cose_err_t
param_decoder(void                   *cb_context,
              QCBORDecodeContext     *cbor_decoder,
              struct t_cose_parameter *param)
{
    switch(param->label) {
        case 44:
            return decode_44(cb_context, cbor_decoder, param);

        default:
            return T_COSE_ERR_FAIL;
    }
}




struct param_test {
    struct q_useful_buf_c    encoded;
    struct t_cose_parameter  unencoded;
    enum t_cose_err_t        encode_result;
    enum t_cose_err_t        decode_result;
    enum t_cose_err_t        check_result;
    int32_t                (*check_cb)(struct t_cose_parameter *param);
    QCBORError               qcbor_encode_result;
};

/* These are like t_cose_param_make_alg_id() and friends, but
 * they work for initialization of static data. */
#define T_COSE_MAKE_ALG_ID_PARAM(alg_id) \
                                {T_COSE_HEADER_PARAM_ALG, \
                                 true,\
                                 false,\
                                 {0,0},\
                                 T_COSE_PARAMETER_TYPE_INT64,\
                                 .value.int64 = alg_id }

#define T_COSE_MAKE_CT_UINT_PARAM(content_type) \
                             {T_COSE_HEADER_PARAM_CONTENT_TYPE, \
                              false,\
                              false,\
                              {0,0},\
                              T_COSE_PARAMETER_TYPE_INT64,\
                              .value.int64 = content_type }


#define T_COSE_MAKE_CT_TSTR_PARAM(content_type) \
                            {T_COSE_HEADER_PARAM_CONTENT_TYPE, \
                             false,\
                             false,\
                             {0,0},\
                             T_COSE_PARAMETER_TYPE_TEXT_STRING,\
                             .value.string = content_type }


#define T_COSE_MAKE_KID_PARAM(kid) \
                              {T_COSE_HEADER_PARAM_KID, \
                              false, \
                              false, \
                              {0,0},\
                              T_COSE_PARAMETER_TYPE_BYTE_STRING, \
                              .value.string = kid }

#define T_COSE_MAKE_IV_PARAM(iv) \
                             {T_COSE_HEADER_PARAM_IV, \
                              false, \
                              false, \
                              {0,0},\
                              T_COSE_PARAMETER_TYPE_BYTE_STRING, \
                              .value.string = iv }

#define T_COSE_MAKE_PARTIAL_IV_PARAM(partial_iv) \
                             {T_COSE_HEADER_PARAM_PARTIAL_IV, \
                              false, \
                              false, \
                              {0,0},\
                              T_COSE_PARAMETER_TYPE_BYTE_STRING, \
                              .value.string = partial_iv }

#define T_COSE_MAKE_END_PARAM  \
                             {0,\
                              false, \
                              false, \
                              {0,0},\
                              T_COSE_PARAMETER_TYPE_NONE, \
                              .value.string = NULL_Q_USEFUL_BUF_C }


static const uint8_t crit_custom_float_param_encoded_cbor[] = {
    0x50, 0xA2, 0x18, 0x2C, 0xFB, 0x40, 0x09, 0x1E, 0xB8, 0x51,
    0xEB, 0x85, 0x1F, 0x02, 0x81, 0x18, 0x2C, 0xA0};

static const uint8_t unprot_bstr_param_encoded_cbor[] = {
    0x41, 0xA0, 0xA1, 0x18, 0x21, 0x43, 0x01, 0x02, 0x03};

static const uint8_t b1[] = {0x01, 0x02, 0x03};

static const uint8_t custom_neg_param_encoded_cbor[] = {
    0x47, 0xA1, 0x0B, 0x3A, 0x7F, 0xFF, 0xFF, 0xFF, 0xA0};

static const uint8_t custom_crit_param_encoded_cbor[] = {
    0x4A, 0xA2, 0x18, 0x4D, 0x19, 0x03, 0x09, 0x02, 0x81, 0x18, 0x4D, 0xA0};

static const uint8_t invalid_params_encoded_cbor[] = {
    0x41, 0x80, 0xA0};

static const uint8_t not_well_formed_params_encoded_cbor[] = {
    0x40, 0xA1, 0x01, 0x1c};

static const uint8_t not_well_formed2_params_encoded_cbor[] = {
    0x40, 0xA1, 0xff};

static const uint8_t missing_prot_param_encoded_cbor[] = {
    0xA1, 0x01, 0x01};

static const uint8_t common_params_encoded_cbor[] = {
    0x52, 0xA3, 0x18, 0x2C, 0xFB, 0x40, 0x09, 0x1E, 0xB8, 0x51,
    0xEB, 0x85, 0x1F, 0x01, 0x26, 0x02, 0x81, 0x18, 0x2C, 0xA5,
    0x18, 0x21, 0x43, 0x01, 0x02, 0x03, 0x03, 0x18, 0x2A, 0x04,
    0x4D, 0x74, 0x68, 0x69, 0x73, 0x2D, 0x69, 0x73, 0x2D, 0x61,
    0x2D, 0x6B, 0x69, 0x64, 0x05, 0x48, 0x69, 0x76, 0x69, 0x76,
    0x69, 0x76, 0x69, 0x76, 0x06, 0x43, 0x70, 0x69, 0x76};

static const uint8_t alg_id_param_encoded_cbor[] = {
    0x43, 0xA1, 0x01, 0x26, 0xA0};

static const uint8_t uint_ct_encoded_cbor[] = {
    0x41, 0xA0, 0xA1, 0x03, 0x18, 0x2A};

static const uint8_t tstr_ct_param_encoded_cbor[] = {
    0x41, 0xA0, 0xA1, 0x03, 0x6A, 0x74, 0x65, 0x78, 0x74, 0x2F,
    0x70, 0x6C, 0x61, 0x69, 0x6E};

static const uint8_t kid_param_encoded_cbor[] = {
    0x41, 0xA0, 0xA1, 0x04, 0x4D, 0x74, 0x68, 0x69, 0x73, 0x2D,
    0x69, 0x73, 0x2D, 0x61, 0x2D, 0x6B, 0x69, 0x64};

static const uint8_t iv_param_encoded_cbor[] = {
    0x41, 0xA0, 0xA1, 0x05, 0x48, 0x69, 0x76, 0x69, 0x76, 0x69,
    0x76, 0x69, 0x76};

static const uint8_t partial_iv_encoded_cbor[] = {
    0x41, 0xA0, 0xA1, 0x06, 0x43, 0x70, 0x69, 0x76};

static const uint8_t not_well_formed_crit_encoded_cbor[] = {
    0x47, 0xA2, 0x18, 0x2c, 0x00, 0x02, 0x81, 0xff, 0xA0};

static const uint8_t empty_crit_encoded_cbor[] = {
    0x46, 0xA2, 0x18, 0x2c, 0x00, 0x02, 0x80, 0xA0};

static const uint8_t wrong_thing_in_crit_encoded_cbor[] = {
    0x47, 0xA2, 0x18, 0x2c, 0x00, 0x02, 0x81, 0x40, 0xA0};

static const uint8_t map_crit_encoded_cbor[] = {
    0x48, 0xA2, 0x18, 0x2c, 0x00, 0x02, 0xa1, 0x00, 0x00, 0xA0};

static const uint8_t crit_unprotected_encoded_cbor[] = {
    0x40, 0xA2, 0x18, 0x2c, 0x00, 0x02, 0x81, 0x0D};

/* If T_COSE_MAX_CRITICAL_PARAMS is increased, the number of items here might
 * also need to be increased. */
static const uint8_t too_many_in_crit_encoded_cbor[] = {
    0x4D, 0xA2, 0x18, 0x2c, 0x00, 0x02, 0x85, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07, 0xA0};

/* If T_COSE_MAX_CRITICAL_PARAMS is increased, the number of items here might
 * also need to be increased. */
static const uint8_t too_many_tstr_in_crit_encoded_cbor[] = {
    0x52, 0xA2, 0x18, 0x2c, 0x00, 0x02, 0x86, 0x61, 0x71, 0x61,
    0x72, 0x05, 0x61, 0x73, 0x61, 0x74, 0x61, 0x75, 0xA0};

/*  */
static const uint8_t iv_and_partial_iv_encoded_cbor[] = {
    0x41, 0xA0, 0xA2, 0x05, 0x48, 0x69, 0x76, 0x69, 0x76, 0x69,
    0x76, 0x69, 0x76, 0x06, 0x41, 0xDD};

static const uint8_t crit_alg_id_encoded_cbor[] = {
    0x46, 0xA2, 0x01, 0x26, 0x02, 0x81, 0x01, 0xA0};

static const uint8_t empty_preferred_encoded_cbor[] = {0x40, 0xA0};

static const uint8_t empty_alt_encoded_cbor[] = {0x41, 0xA0, 0xA0};

#if FIXES_FOR_INDEF_LEN
static const uint8_t empty_preferred_indef[] = {0x5f, 0xff, 0xbf, 0xff};

static const uint8_t empty_alt_indef[] = {0x5f, 0xbf, 0xff, 0xff, 0xbf, 0xff};
#endif


/* Alternative to UsefulBuf_FROM_BYTE_ARRAY_LITERAL() &
 * UsefulBuf_FROM_SZ_LITERAL()that works for static data initialization. */
#define UBX(x) {x, sizeof(x)}
#define UBS(x) {x, sizeof(x)-1}


#define NO_ENCODE_TEST 253 /* A special parameter type to not encode */


static const struct param_test param_tests[] = {
    /* 0. Critical, protected floating point parameter made by callback. */
    {
        UBX(crit_custom_float_param_encoded_cbor),
        {44, true, true, {0,0}, T_COSE_PARAMETER_TYPE_SPECIAL, .value.special_encode = {param_encoder, {NULL}}, NULL },
        T_COSE_SUCCESS,
        T_COSE_SUCCESS,
        T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER, /* Expected check result */
        check_44,
        QCBOR_SUCCESS
    },

    /* 1. Simple unprotected byte string parameter. */
    {
        UBX(unprot_bstr_param_encoded_cbor),
        {33, false, false, {0,0}, T_COSE_PARAMETER_TYPE_BYTE_STRING,
            .value.string = UBX(b1), NULL},
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        T_COSE_SUCCESS, /* Expected check result */
        NULL,
        QCBOR_SUCCESS
    },

    /* 2. Trying to make a parameter of an unknown type. */
    {
        {empty_preferred_encoded_cbor, 0}, /* Unused */
        {22, false, false, {0,0}, 200 /* Unknown type */, .value.int64 = 11, NULL},
        T_COSE_ERR_INVALID_PARAMETER_TYPE,
        0,
        0,
        NULL,
        QCBOR_SUCCESS
    },

    /* 3. A protected negative integer parameter. */
    {
        UBX(custom_neg_param_encoded_cbor), /* CBOR encoded header params */
        {11, true, false, {0,0}, T_COSE_PARAMETER_TYPE_INT64, .value.int64 = INT32_MIN, NULL},
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        T_COSE_SUCCESS, /* Expected check result */
        NULL, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 4. Attempt to encode a critical unprotected parameter. */
    {
        {empty_preferred_encoded_cbor, 0}, /* Unused */
        {101, false, true, {0,0}, T_COSE_PARAMETER_TYPE_INT64, .value.int64 = INT32_MIN, NULL},
        T_COSE_ERR_CRIT_PARAMETER_IN_UNPROTECTED, /* Expected encode result */
        0, /* Expected decode result */
        0, /* Expected check result */
        NULL, /* Call back for decode check */
        0 /* Expected CBOR encode result */
    },

    /* 5. Encoder callback returns an error. */
    {
        {empty_preferred_encoded_cbor, 0}, /* Unused */
        {55, true, true, {0,0}, T_COSE_PARAMETER_TYPE_SPECIAL, .value.special_encode = {param_encoder, {NULL}}, NULL },
        T_COSE_ERR_FAIL, /* Expected encode result */
        0, /* Expected decode result */
        0, /* Expected check result */
        NULL, /* Call back for decode check */
        0 /* Expected CBOR encode result */
    },

    /* 6. Encoder callback produces invalid CBOR. */
    {
        {empty_preferred_encoded_cbor, 0}, /* Unused */
        {66, true, true, {0,0}, T_COSE_PARAMETER_TYPE_SPECIAL, .value.special_encode = {param_encoder, {NULL}}, NULL },
        T_COSE_SUCCESS, /* Expected encode result */
        0, /* Expected decode result */
        0, /* Expected check result */
        NULL, /* Call back for decode check */
        QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN /* Expected CBOR encode result */
    },

    /* 7. Incorrectly formatted parameters (decode only test) */
    {
        UBX(invalid_params_encoded_cbor), /* CBOR encoded header params */
        {0, false, false, {0,0}, NO_ENCODE_TEST, .value.int64 = 0, NULL},
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_ERR_PARAMETER_CBOR, /* Expected decode result */
        T_COSE_SUCCESS, /* Expected check result */
        NULL, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 8. Not-well formed parameters (decode only test) */
    {
        UBX(not_well_formed_params_encoded_cbor), /* CBOR encoded hdr params */
        {0, false, false, {0,0}, NO_ENCODE_TEST, .value.int64 = 0},
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_ERR_CBOR_NOT_WELL_FORMED, /* Expected decode result */
        T_COSE_SUCCESS, /* Expected check result */
        NULL, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 9. Not-well formed parameters (decode only test) */
    {
        UBX(not_well_formed2_params_encoded_cbor), /* CBOR encoded hdr params */
        {0, false, false, {0,0}, NO_ENCODE_TEST, .value.int64 = 0, NULL},
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_ERR_CBOR_NOT_WELL_FORMED, /* Expected decode result */
        T_COSE_SUCCESS, /* Expected check result */
        NULL, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 10. No protected headers at all (decode only test) */
    {
        UBX(missing_prot_param_encoded_cbor), /* CBOR encoded header params */
        {0, false, false, {0,0}, NO_ENCODE_TEST, .value.int64 = 0, NULL},
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_ERR_PARAMETER_CBOR, /* Expected decode result */
        T_COSE_SUCCESS, /* Expected check result */
        NULL, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 11. an algorithm ID  */
    {
        UBX(alg_id_param_encoded_cbor), /* CBOR encoded header params */
        T_COSE_MAKE_ALG_ID_PARAM(T_COSE_ALGORITHM_ES256),
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        T_COSE_SUCCESS, /* Expected check result */
        check_alg_id, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 12. an integer content ID  */
    {
        UBX(uint_ct_encoded_cbor), /* CBOR encoded header params */
        T_COSE_MAKE_CT_UINT_PARAM(42),
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        T_COSE_SUCCESS, /* Expected check result */
        check_int_content_id, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 13. text string content ID  */
    {
        UBX(tstr_ct_param_encoded_cbor), /* CBOR encoded header params */
        T_COSE_MAKE_CT_TSTR_PARAM(UBS("text/plain")),
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        T_COSE_SUCCESS, /* Expected check result */
        check_text_content_id, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 14. kid  */
    {
        UBX(kid_param_encoded_cbor), /* CBOR encoded header params */
        T_COSE_MAKE_KID_PARAM(UBS("this-is-a-kid")),
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        T_COSE_SUCCESS, /* Expected check result */
        check_kid, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 15. IV */
    {
        UBX(iv_param_encoded_cbor), /* CBOR encoded header params */
        T_COSE_MAKE_IV_PARAM(UBS("iviviviv")),
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        T_COSE_SUCCESS, /* Expected check result */
        check_iv, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 16. Partial IV */
    {
        UBX(partial_iv_encoded_cbor), /* CBOR encoded header params */
        T_COSE_MAKE_PARTIAL_IV_PARAM(UBS("piv")),
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        T_COSE_SUCCESS, /* Expected check result */
        check_partial_iv, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 17. Critical parameter with no callback to handle it. */
    {
        UBX(custom_crit_param_encoded_cbor), /* CBOR encoded header params */
        {77, true, true, {0,0}, T_COSE_PARAMETER_TYPE_INT64, .value.int64 = 777, NULL},
        T_COSE_SUCCESS, /* Expected encode result */
        0, /* Expected decode result */
        T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER, /* Expected check result */
        NULL, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 18. Crit param is not well formed (decode only test). */
    {
        UBX(not_well_formed_crit_encoded_cbor),
        {0, false, false, {0,0}, NO_ENCODE_TEST, .value.int64 = 0, NULL},
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_ERR_CRIT_PARAMETER, /* Expected decode result */
        T_COSE_SUCCESS, /* Expected check result */
        NULL, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 19. Crit param is empty (decode only test). */
    {
         UBX(empty_crit_encoded_cbor),
         {0, false, false, {0,0}, NO_ENCODE_TEST, .value.int64 = 0, NULL},
         T_COSE_SUCCESS, /* Expected encode result */
         T_COSE_ERR_CRIT_PARAMETER, /* Expected decode result */
         T_COSE_SUCCESS, /* Expected check result */
         NULL, /* Call back for decode check */
         QCBOR_SUCCESS /* Expected CBOR encode result */
     },

    /* 20. Crit param has wrong thing in it (decode only test). */
    {
         UBX(wrong_thing_in_crit_encoded_cbor),
         {0, false, false, {0,0}, NO_ENCODE_TEST, .value.int64 = 0, NULL},
         T_COSE_SUCCESS, /* Expected encode result */
         T_COSE_ERR_CRIT_PARAMETER, /* Expected decode result */
         T_COSE_SUCCESS, /* Expected check result */
         NULL, /* Call back for decode check */
         QCBOR_SUCCESS /* Expected CBOR encode result */
     },

    /* 21. Crit param is map (decode only test). */
    {
         UBX(map_crit_encoded_cbor),
         {0, false, false, {0,0}, NO_ENCODE_TEST, .value.int64 = 0, NULL},
         T_COSE_SUCCESS, /* Expected encode result */
         T_COSE_ERR_CRIT_PARAMETER, /* Expected decode result */
         T_COSE_SUCCESS, /* Expected check result */
         NULL, /* Call back for decode check */
         QCBOR_SUCCESS /* Expected CBOR encode result */
     },

    /* 22. Crit param is unprotected (decode only test). */
    {
         UBX(crit_unprotected_encoded_cbor),
         {0, false, false, {0,0}, NO_ENCODE_TEST, .value.int64 = 0, NULL},
         T_COSE_SUCCESS, /* Expected encode result */
         T_COSE_ERR_PARAMETER_NOT_PROTECTED, /* Expected decode result */
         T_COSE_SUCCESS, /* Expected check result */
         NULL, /* Call back for decode check */
         QCBOR_SUCCESS /* Expected CBOR encode result */
     },

    /* 23. Too many ints in crit (decode only test). */
    {
         UBX(too_many_in_crit_encoded_cbor),
         {0, false, false, {0,0}, NO_ENCODE_TEST, .value.int64 = 0, NULL},
         T_COSE_SUCCESS, /* Expected encode result */
         T_COSE_ERR_CRIT_PARAMETER, /* Expected decode result */
         T_COSE_SUCCESS, /* Expected check result */
         NULL, /* Call back for decode check */
         QCBOR_SUCCESS /* Expected CBOR encode result */
     },

    /* 24. Too many tstr in crit (decode only test). */
    {
         UBX(too_many_tstr_in_crit_encoded_cbor),
         {0, false, false, {0,0}, NO_ENCODE_TEST, .value.int64 = 0, NULL},
         T_COSE_SUCCESS, /* Expected encode result */
         T_COSE_ERR_CRIT_PARAMETER, /* Expected decode result */
         T_COSE_SUCCESS, /* Expected check result */
         NULL, /* Call back for decode check */
         QCBOR_SUCCESS /* Expected CBOR encode result */
     },

    /* 25. Both IV and partial IV to test t_cose_params_check() */
    {
         UBX(iv_and_partial_iv_encoded_cbor),
         {0, false, false, {0,0}, NO_ENCODE_TEST, .value.int64 = 0, NULL},
         T_COSE_SUCCESS, /* Expected encode result */
         T_COSE_SUCCESS, /* Expected decode result */
         T_COSE_ERR_DUPLICATE_PARAMETER, /* Expected check result */
         NULL, /* Call back for decode check */
         QCBOR_SUCCESS /* Expected CBOR encode result */
     },

    /* 26. alg id marked crit */
    {
        UBX(crit_alg_id_encoded_cbor), /* CBOR encoded header params */
        {0, false, false, {0,0}, NO_ENCODE_TEST, .value.int64 = 0, NULL},
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        T_COSE_SUCCESS, /* Expected check result */
        NULL, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 27. preferred empty protected parameters */
    {
        UBX(empty_preferred_encoded_cbor), /* CBOR encoded header params */
        {0, false, false, {0,0}, NO_ENCODE_TEST, .value.int64 = 0, NULL},
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        T_COSE_SUCCESS, /* Expected check result */
        check_empty, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 28. Alt empty protected parameters  */
    {
        UBX(empty_alt_encoded_cbor), /* CBOR encoded header params */
        {0, false, false, {0,0}, NO_ENCODE_TEST, .value.int64 = 0, NULL},
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        T_COSE_SUCCESS, /* Expected check result */
        check_empty, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

#if FIXES_FOR_INDEF_LEN
    /* 29. Alt empty protected parameters  */
    {
        UBX(empty_preferred_indef), /* CBOR encoded header params */
        {0, false, false, {0,0}, NO_ENCODE_TEST, .value.int64 = 0, NULL},
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        T_COSE_SUCCESS, /* Expected check result */
        check_empty, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 30. preferred empty indef protected parameters */
    {
        UBX(empty_alt_indef), /* CBOR encoded header params */
        {0, false, false, {0,0}, NO_ENCODE_TEST, .value.int64 = 0, NULL},
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        T_COSE_SUCCESS, /* Expected check result */
        check_empty, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },
#endif /* FIXES_FOR_INDEF_LEN */

    /* Terminator */
    {
        {NULL, 0},
        {0, false, false, {0,0}, NO_ENCODE_TEST, .value.int64 = 0},
        0,
        0,
        0,
        NULL,
        0
    }
};


struct param_test_combo {
    struct q_useful_buf_c  encoded;
    int                   *combo_list; /* Array of values  that index into
                                        * param_tests terminated by MAX_INT */
    enum t_cose_err_t      header_encode_result;
    QCBORError             qcbor_encode_result;
};

static struct param_test_combo param_combo_tests[] = {
    /* 0. Encode duplicate parameters */
    {
        UBX(unprot_bstr_param_encoded_cbor),
        (int []){0, 0, INT_MAX},
        T_COSE_ERR_DUPLICATE_PARAMETER,
        QCBOR_SUCCESS,
    },
    /* 1. Several parameters success test */
    {
        UBX(common_params_encoded_cbor),
        (int []){0, 1, 11, 12, 14, 15, 16, INT_MAX},
        T_COSE_SUCCESS,
        QCBOR_SUCCESS,
    },

    {
        {NULL, 0},
        NULL,
        0,
        0
    }
};




int32_t
param_test(void)
{
    struct t_cose_parameter         param_array[20];
    struct q_useful_buf_c           encoded_params;
    enum t_cose_err_t               t_cose_result;
    QCBORError                      qcbor_result;
    QCBOREncodeContext              qcbor_encoder;
    Q_USEFUL_BUF_MAKE_STACK_UB(     encode_buffer, 200);
    const struct param_test        *param_test;
    QCBORDecodeContext              decode_context;
    struct q_useful_buf_c           encoded_prot_params;
    struct t_cose_parameter_storage param_storage;
    struct t_cose_parameter        *decoded_parameter;


    /* Test is driven by data in param_tests and param_combo_tests.
     * This is all a bit more complicated than expected, but it is
     * a data driven tests. */

    /* The single parameter tests */
    for(int i = 0; ; i++) {
        param_test = &param_tests[i];
        if(q_useful_buf_c_is_null(param_test->encoded)) {
            break;
        }

        /* This is just to be able to set break points by test number. */
        if(i == 29) {
            t_cose_result = 0;
        }

        /* Encode test */
        if(param_test->unencoded.value_type != NO_ENCODE_TEST) {
            QCBOREncode_Init(&qcbor_encoder, encode_buffer);
            t_cose_result = t_cose_headers_encode(&qcbor_encoder,
                                                  &(param_test->unencoded),
                                                  NULL);

            if(t_cose_result != param_test->encode_result) {
                return i * 1000 + 1;
            }

            if(t_cose_result == T_COSE_SUCCESS) {
                qcbor_result = QCBOREncode_Finish(&qcbor_encoder,
                                                  &encoded_params);
                if(qcbor_result != param_test->qcbor_encode_result) {
                    return i * 1000 + 2;
                }

                if(qcbor_result == QCBOR_SUCCESS) {
                    if(q_useful_buf_compare(encoded_params, param_test->encoded)) {
                        return i * 1000 + 3;
                    }
                }
            }
        }

        /* Decode test */
        if(!q_useful_buf_c_is_empty(param_test->encoded)) {
            T_COSE_PARAM_STORAGE_INIT(param_storage, param_array);

            QCBORDecode_Init(&decode_context, param_test->encoded, 0);


            UsefulBuf_MAKE_STACK_UB(Pool, 100);

            QCBORDecode_SetMemPool(&decode_context, Pool, 0);


            decoded_parameter = NULL;

            t_cose_result = t_cose_headers_decode(&decode_context,
                                                   (struct t_cose_header_location){0,0},
                                                   param_decoder,
                                                   NULL,
                                                  &param_storage,
                                                  &decoded_parameter,
                                                  &encoded_prot_params);

            if(t_cose_result != param_test->decode_result) {
                return i * 1000 + 4;
            }

            if(t_cose_result == T_COSE_SUCCESS) {
                if(param_test->check_cb) {
                    int32_t r;
                    r = param_test->check_cb(decoded_parameter);
                    if(r) {
                        return i * 1000 + 10 + r;
                    }
                } else if(param_test->unencoded.value_type != NO_ENCODE_TEST) {
                    if(decoded_parameter->value_type != param_test->unencoded.value_type) {
                        return i * 1000;
                    }
                    switch(decoded_parameter->value_type) {
                        case T_COSE_PARAMETER_TYPE_INT64:
                            if(decoded_parameter->value.int64 != param_test->unencoded.value.int64) {
                                return i * 1000 + 5;
                            }
                            break;

                        case T_COSE_PARAMETER_TYPE_TEXT_STRING:
                        case T_COSE_PARAMETER_TYPE_BYTE_STRING:
                            if(q_useful_buf_compare(decoded_parameter->value.string,
                                                    param_test->unencoded.value.string)) {
                                return i * 1000 + 6;
                            }
                            break;
                    }
                }

                if(t_cose_params_check(decoded_parameter) != param_test->check_result) {
                    return i * 1000 + 7;
                }
            }
        }
    }


    /* The multiple parameter tests */
    for(int i = 0; ; i++) {
        struct param_test_combo *ppp = &param_combo_tests[i];

        if(ppp->combo_list == NULL) {
            break;
        }

        /* This is just to be able to set a break point by test number. */
        if(i == 1) {
            t_cose_result = 0;
        }

        int j;
        for(j = 0; ppp->combo_list[j] != INT_MAX; j++) {
            param_array[j] = param_tests[ppp->combo_list[j]].unencoded;
            if(j != 0) {
                param_array[j-1].next = &param_array[j];
            }
        }

        QCBOREncode_Init(&qcbor_encoder, encode_buffer);
        t_cose_result = t_cose_headers_encode(&qcbor_encoder,
                                              param_array,
                                              NULL);

        if(t_cose_result != ppp->header_encode_result) {
            return i * 100000 + 1;
        }

        qcbor_result = QCBOREncode_Finish(&qcbor_encoder, &encoded_params);
        if(qcbor_result != ppp->qcbor_encode_result) {
            return i * 100000 + 2;
        }

        if(t_cose_result == T_COSE_SUCCESS && qcbor_result == QCBOR_SUCCESS) {
            if(q_useful_buf_compare(encoded_params, ppp->encoded)) {
                return i * 100000 + 3;
            }
        }

        // Could do some decode tests here, but so far not
        // a real need.
    }


    /* Empty parameters section test */
    QCBOREncode_Init(&qcbor_encoder, encode_buffer);
    t_cose_result = t_cose_headers_encode(&qcbor_encoder,
                                          NULL,
                                          NULL);

    if(t_cose_result != param_test->encode_result) {
        return -900;
    }

    if(t_cose_result == T_COSE_SUCCESS) {
        qcbor_result = QCBOREncode_Finish(&qcbor_encoder, &encoded_params);
        if(qcbor_result != param_test->qcbor_encode_result) {
            return -900;
        }

        if(qcbor_result == QCBOR_SUCCESS) {
            if(q_useful_buf_compare(encoded_params, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(empty_alt_encoded_cbor))) {
                return -900;
            }
        }

        T_COSE_PARAM_STORAGE_INIT(param_storage, param_array);

        decoded_parameter = NULL;

        QCBORDecode_Init(&decode_context, encoded_params, 0);

        t_cose_result = t_cose_headers_decode(&decode_context,
                                              (struct t_cose_header_location){0,0},
                                              param_decoder, NULL,
                                             &param_storage,
                                             &decoded_parameter,
                                             &encoded_prot_params);

        if(t_cose_result != T_COSE_SUCCESS) {
            return -700;
        }

        if(decoded_parameter != NULL) {
            return -900;
        }
    }

    return 0;
}




int32_t
common_params_test(void)
{
    struct t_cose_parameter         param_array[20];
    struct q_useful_buf_c           encoded_params;
    enum t_cose_err_t               t_cose_result;
    QCBORError                      qcbor_result;
    QCBOREncodeContext              qcbor_encoder;
    Q_USEFUL_BUF_MAKE_STACK_UB(     encode_buffer, 200);
    QCBORDecodeContext              decode_context;
    struct q_useful_buf_c           encoded_prot_params;
    struct q_useful_buf_c           string;
    struct t_cose_parameter_storage param_storage;
    struct t_cose_parameter        *dec;
    struct t_cose_parameters        common_params;

    /*  --- Make a list of the common parameters defined in 9052 --- */
    param_array[0] = param_tests[1].unencoded;

    param_array[1] = t_cose_param_make_ct_uint(42);
    param_array[0].next = &param_array[1];

    param_array[2] = t_cose_param_make_kid(Q_USEFUL_BUF_FROM_SZ_LITERAL("this-is-a-kid"));
    param_array[1].next = &param_array[2];

    param_array[3] = t_cose_param_make_iv(Q_USEFUL_BUF_FROM_SZ_LITERAL("iviviviv"));
    param_array[2].next = &param_array[3];

    param_array[4] = t_cose_param_make_partial_iv(Q_USEFUL_BUF_FROM_SZ_LITERAL("piv"));
    param_array[3].next = &param_array[4];

    param_array[5] = param_tests[0].unencoded;
    param_array[4].next = &param_array[5];

    param_array[6] = t_cose_param_make_alg_id(T_COSE_ALGORITHM_ES256);
    param_array[5].next = &param_array[6];

    /* --- Encode them and make sure the CBOR is as expected --- */
    QCBOREncode_Init(&qcbor_encoder, encode_buffer);
    t_cose_result = t_cose_headers_encode(&qcbor_encoder,
                                          &param_array[0],
                                          NULL);

    if(t_cose_result != T_COSE_SUCCESS) {
        return -1;
    }

    qcbor_result = QCBOREncode_Finish(&qcbor_encoder, &encoded_params);
    if(qcbor_result != QCBOR_SUCCESS) {
        return -2;
    }

    if(q_useful_buf_compare(encoded_params, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(common_params_encoded_cbor))) {
        return -3;
    }

    /* --- Decode what was encoded ---*/
    if(t_cose_param_find_alg_id(NULL, true) != T_COSE_ALGORITHM_NONE) {
        return -4;
    }

    if(t_cose_param_find_content_type_uint(NULL) != T_COSE_EMPTY_UINT_CONTENT_TYPE) {
        return -5;
    }

    if(!q_useful_buf_c_is_null(t_cose_param_find_kid(NULL))) {
        return -6;
    }

    if(!q_useful_buf_c_is_null(t_cose_param_find_iv(NULL))) {
        return -7;
    }

    if(!q_useful_buf_c_is_null(t_cose_param_find_partial_iv(NULL))) {
        return -8;
    }

    QCBORDecode_Init(&decode_context, encoded_params, 0);

    T_COSE_PARAM_STORAGE_INIT(param_storage,param_array);
    dec = NULL;

    t_cose_result = t_cose_headers_decode(&decode_context,
                                          (struct t_cose_header_location){0,0},
                                          NULL,
                                          NULL,
                                          &param_storage,
                                          &dec,
                                          &encoded_prot_params);

    qcbor_result = QCBORDecode_Finish(&decode_context);
    if(qcbor_result != QCBOR_SUCCESS) {
        return -9;
    }
    if(t_cose_result != T_COSE_SUCCESS) {
        return -10;
    }

    /* Check that they decoded correctly */
    if(t_cose_param_find_alg_id(dec, true) != T_COSE_ALGORITHM_ES256) {
        return -11;
    }

    if(t_cose_param_find_content_type_uint (dec) != 42) {
        return -12;
    }

    string = t_cose_param_find_kid(dec);
    if(q_useful_buf_compare(string, Q_USEFUL_BUF_FROM_SZ_LITERAL("this-is-a-kid"))) {
        return -13;
    }

    string = t_cose_param_find_iv(dec);
    if(q_useful_buf_compare(string, Q_USEFUL_BUF_FROM_SZ_LITERAL("iviviviv"))) {
        return -14;
    }

    string = t_cose_param_find_partial_iv(dec);
    if(q_useful_buf_compare(string, Q_USEFUL_BUF_FROM_SZ_LITERAL("piv"))) {
        return -15;
    }

    if(t_cose_params_common(dec, &common_params) != T_COSE_ERR_DUPLICATE_PARAMETER) {
        /* It is supposed to be duplicate because of iv and partial_iv */
        return -16;
    }


    /* --- Do it again for parameters that can't exist with those above --- */
    param_array[0] = t_cose_param_make_ct_tstr(Q_USEFUL_BUF_FROM_SZ_LITERAL("text/foo"));

    param_array[1] = t_cose_param_make_kid(Q_USEFUL_BUF_FROM_SZ_LITERAL("this-is-a-kid"));
    param_array[0].next = &param_array[1];

    param_array[2] = t_cose_param_make_iv(Q_USEFUL_BUF_FROM_SZ_LITERAL("iviviviv"));
    param_array[1].next = &param_array[2];

    param_array[3] = t_cose_param_make_alg_id(T_COSE_ALGORITHM_ES256);
    param_array[2].next = &param_array[3];

    /* --- Encode them and make sure the CBOR is as expected --- */
    QCBOREncode_Init(&qcbor_encoder, encode_buffer);
    t_cose_result = t_cose_headers_encode(&qcbor_encoder,
                                          &param_array[0],
                                          NULL);

    if(t_cose_result != T_COSE_SUCCESS) {
        return -21;
    }

    qcbor_result = QCBOREncode_Finish(&qcbor_encoder, &encoded_params);
    if(qcbor_result != QCBOR_SUCCESS) {
        return -22;
    }

   /* Don't bother with comparison to expected the second time */

    /* --- Decode what was encoded ---*/
    QCBORDecode_Init(&decode_context, encoded_params, 0);

    T_COSE_PARAM_STORAGE_INIT(param_storage,param_array);
    dec = NULL;

    t_cose_result = t_cose_headers_decode(&decode_context,
                                          (struct t_cose_header_location){0,0},
                                          NULL,
                                          NULL,
                                          &param_storage,
                                          &dec,
                                          &encoded_prot_params);

    qcbor_result = QCBORDecode_Finish(&decode_context);
    if(qcbor_result != QCBOR_SUCCESS) {
        return -23;
    }
    if(t_cose_result != T_COSE_SUCCESS) {
        return -24;
    }


    t_cose_result = t_cose_params_common(dec, &common_params);
    if(t_cose_result != T_COSE_SUCCESS) {
        return -25;
    }

    if(common_params.cose_algorithm_id != T_COSE_ALGORITHM_ES256) {
        return -50;
    }

    if(q_useful_buf_compare(common_params.kid, Q_USEFUL_BUF_FROM_SZ_LITERAL("this-is-a-kid"))) {
        return -53;
    }

#ifndef T_COSE_DISABLE_CONTENT_TYPE
    if(q_useful_buf_compare(common_params.content_type_tstr, Q_USEFUL_BUF_FROM_SZ_LITERAL("text/foo"))) {
        return -54;
    }
#endif /* !T_COSE_DISABLE_CONTENT_TYPE */

    if(q_useful_buf_compare(common_params.iv, Q_USEFUL_BUF_FROM_SZ_LITERAL("iviviviv"))) {
        return -55;
    }

    if(!q_useful_buf_c_is_null(common_params.partial_iv)) {
        return -57;
    }

    return 0;
}
