//
//  t_cose_param_test.c
//  t_cose_test
//
//  Created by Laurence Lundblade on 9/20/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#include "t_cose_param_test.h"

#include "t_cose/t_cose_parameters.h"

#include <limits.h>
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose/q_useful_buf.h"

#include "t_cose/t_cose_standard_constants.h" // TODO: change path when this becomes public


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
decode_44(void                       *callback_context,
          QCBORDecodeContext         *qcbor_decoder,
          struct t_cose_parameter *p)
{
    double  d;

    (void)callback_context;

    QCBORDecode_GetDouble(qcbor_decoder, &d);
    // Stuff the double into the little buf
    // because that's what we're doing for label 44 floats.
    memcpy(p->value.little_buf, &d, sizeof(d));
    p->value_type = T_COSE_PARAMETER_TYPE_LITTLE_BUF;
    return T_COSE_SUCCESS;
}

static int32_t
check_44(struct t_cose_parameter *param)
{
    if(param->label != 44) {
        return 1;
    }

    if(param->value_type != T_COSE_PARAMETER_TYPE_LITTLE_BUF) {
        return 2;
    }
    /* Have to have some comparision function in the test case. */
    double d;
    memcpy(&d, param->value.little_buf, sizeof(d));

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

    if(param->value.i64 != T_COSE_ALGORITHM_ES256) {
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

    if(param->value.i64 != 42) {
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

static enum t_cose_err_t
param_encoder(void                           *cb_context,
              const struct t_cose_parameter  *param,
              QCBOREncodeContext             *cbor_encoder)
{
    (void)cb_context;
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
    struct q_useful_buf_c       encoded;
    struct t_cose_parameter  unencoded;
    enum t_cose_err_t           encode_result;
    enum t_cose_err_t           decode_result;
    int32_t                     (*check_cb)(struct t_cose_parameter *param);
    QCBORError                  qcbor_encode_result;
};




#define T_COSE_MAKE_ALG_ID_PARAM(alg_id) \
                                {T_COSE_HEADER_PARAM_ALG, \
                                 true,\
                                 false,\
                                 {0,0},\
                                 T_COSE_PARAMETER_TYPE_INT64,\
                                 .value.i64 = alg_id }


//#ifndef T_COSE_DISABLE_CONTENT_TYPE


#define T_COSE_MAKE_CT_UINT_PARAM(content_type) \
                             {T_COSE_HEADER_PARAM_CONTENT_TYPE, \
                              false,\
                              false,\
                              {0,0},\
                              T_COSE_PARAMETER_TYPE_INT64,\
                              .value.i64 = content_type }



#define T_COSE_MAKE_CT_TSTR_PARAM(content_type) \
                            {T_COSE_HEADER_PARAM_CONTENT_TYPE, \
                             false,\
                             false,\
                             {0,0},\
                             T_COSE_PARAMETER_TYPE_TEXT_STRING,\
                             .value.string = content_type }
//#endif /* T_COSE_DISABLE_CONTENT_TYPE */



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

static const uint8_t x1[] = {0x50, 0xA2, 0x18, 0x2C, 0xFB, 0x40, 0x09, 0x1E, 0xB8, 0x51, 0xEB, 0x85, 0x1F, 0x02, 0x81, 0x18, 0x2C, 0xA0};

static const uint8_t x2[] = {0x41, 0xA0, 0xA1, 0x18, 0x21, 0x43, 0x01, 0x02, 0x03};

static const uint8_t b1[] = {0x01, 0x02, 0x03};

static const uint8_t x3[] = {0x47, 0xA1, 0x0B, 0x3A, 0x7F, 0xFF, 0xFF, 0xFF, 0xA0};

#ifdef TODO_CRIT_PARAM_FIXED
static const uint8_t x4[] = {0x4A, 0xA2, 0x18, 0x4D, 0x19, 0x03, 0x09, 0x02, 0x81, 0x18, 0x4D, 0xA0};
#endif

static const uint8_t x5[] = {0x41, 0xA0, 0xA0};

static const uint8_t x6[] = {0x41, 0x80, 0xA0};

static const uint8_t x7[] = {0x40, 0xA1, 0x01, 0x1c};

static const uint8_t x8[] = {0x40, 0xA1, 0xff};

static const uint8_t x9[] = {0xA1, 0x01, 0x01};

static const uint8_t x10[] = {0x52, 0xA3, 0x18, 0x2C, 0xFB, 0x40, 0x09, 0x1E, 0xB8, 0x51, 0xEB, 0x85, 0x1F, 0x01, 0x26, 0x02, 0x81, 0x18, 0x2C, 0xA5, 0x18, 0x21, 0x43, 0x01, 0x02, 0x03, 0x03, 0x18, 0x2A, 0x04, 0x4D, 0x74, 0x68, 0x69, 0x73, 0x2D, 0x69, 0x73, 0x2D, 0x61, 0x2D, 0x6B, 0x69, 0x64, 0x05, 0x48, 0x69, 0x76, 0x69, 0x76, 0x69, 0x76, 0x69, 0x76, 0x06, 0x43, 0x70, 0x69, 0x76};


static const uint8_t x11[] = {0x43, 0xA1, 0x01, 0x26, 0xA0};

static const uint8_t x12[] = {0x41, 0xA0, 0xA1, 0x03, 0x18, 0x2A};

static const uint8_t x13[] = {0x41, 0xA0, 0xA1, 0x03, 0x6A, 0x74, 0x65, 0x78, 0x74, 0x2F, 0x70, 0x6C, 0x61, 0x69, 0x6E};


static const uint8_t x14[] = {0x41, 0xA0, 0xA1, 0x04, 0x4D, 0x74, 0x68, 0x69, 0x73, 0x2D, 0x69, 0x73, 0x2D, 0x61, 0x2D, 0x6B, 0x69, 0x64};

static const uint8_t x15[] = {0x41, 0xA0, 0xA1, 0x05, 0x48, 0x69, 0x76, 0x69, 0x76, 0x69, 0x76, 0x69, 0x76};

static const uint8_t x16[] = {0x41, 0xA0, 0xA1, 0x06, 0x43, 0x70, 0x69, 0x76};


#define UBX(x) {x, sizeof(x)}
#define UBS(x) {x, sizeof(x)-1}


#define NO_ENCODE_TEST 253 /* A special parameter type to not encode */


static const struct param_test param_tests[] = {
    /* 0. Critical, protected floating point parameter made by callback. */
    {
        UBX(x1),
        {44, true, true, {0,0}, T_COSE_PARAMETER_TYPE_CALLBACK, .value.custom_encoder = {NULL, param_encoder}, NULL },
        T_COSE_SUCCESS,
        T_COSE_SUCCESS,
        check_44,
        QCBOR_SUCCESS
    },

    /* 1. Simple unprotected byte string parameter. */
    {
        UBX(x2),
        {33, false, false, {0,0}, T_COSE_PARAMETER_TYPE_BYTE_STRING,
            .value.string = UBX(b1), NULL},
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        NULL,
        QCBOR_SUCCESS
    },

    /* 2. Trying to make a parameter of an unknown type. */
    {
        {x2, 0}, // Unused
        {22, false, false, {0,0}, 200 /* Unknown type */, .value.i64 = 11, NULL},
        T_COSE_ERR_INVALID_PARAMETER_TYPE,
        0,
        NULL,
        QCBOR_SUCCESS
    },

    /* 3. A protected negative integer parameter. */
    {
        UBX(x3), /* CBOR encoded header params */
        {11, true, false, {0,0}, T_COSE_PARAMETER_TYPE_INT64, .value.i64 = INT32_MIN, NULL},
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        NULL, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 4. Attempt to encode a critical unprotected parameter. */
    {
        {x2, 0}, // Unused
        {101, false, true, {0,0}, T_COSE_PARAMETER_TYPE_INT64, .value.i64 = INT32_MIN, NULL},
        T_COSE_ERR_CRIT_PARAMETER_IN_UNPROTECTED, /* Expected encode result */
        0, /* Expected decode result */
        NULL, /* Call back for decode check */
        0 /* Expected CBOR encode result */
    },

    /* 5. Encoder callback returns an error. */
    {
        {x2, 0}, // Unused
        {55, true, true, {0,0}, T_COSE_PARAMETER_TYPE_CALLBACK, .value.custom_encoder = {NULL, param_encoder}, NULL },
        T_COSE_ERR_FAIL, /* Expected encode result */
        0, /* Expected decode result */
        NULL, /* Call back for decode check */
        0 /* Expected CBOR encode result */
    },

    /* 6. Encoder callback produces invalid CBOR. */
    {
        {x2, 0}, // Unused
        {66, true, true, {0,0}, T_COSE_PARAMETER_TYPE_CALLBACK, .value.custom_encoder = {NULL, param_encoder}, NULL },
        T_COSE_SUCCESS, /* Expected encode result */
        0, /* Expected decode result */
        NULL, /* Call back for decode check */
        QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN /* Expected CBOR encode result */
    },

    // TODO: renumber tests
    // TODO: test for empty parameters



    /* 8. Incorrectly formatted parameters (decode only test) */
    {
        UBX(x6), /* CBOR encoded header params */
        {0, false, false, {0,0}, NO_ENCODE_TEST, .value.ptr = NULL, NULL},
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_ERR_PARAMETER_CBOR, /* Expected decode result */
        NULL, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 9. Not-well formed parameters (decode only test) */
    {
        UBX(x7), /* CBOR encoded header params */
        {0, false, false, {0,0}, NO_ENCODE_TEST, .value.ptr = NULL},
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_ERR_CBOR_NOT_WELL_FORMED, /* Expected decode result */
        NULL, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 10. Not-well formed parameters (decode only test) */
    {
        UBX(x8), /* CBOR encoded header params */
        {0, false, false, {0,0}, NO_ENCODE_TEST, .value.ptr = NULL, NULL},
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_ERR_CBOR_NOT_WELL_FORMED, /* Expected decode result */
        NULL, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 11. No protected headers at all (decode only test) */
    {
        UBX(x9), /* CBOR encoded header params */
        {0, false, false, {0,0}, NO_ENCODE_TEST, .value.ptr = NULL, NULL},
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_ERR_PARAMETER_CBOR, /* Expected decode result */
        NULL, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 12. an algorithm ID  */
    {
        UBX(x11), /* CBOR encoded header params */
        T_COSE_MAKE_ALG_ID_PARAM(T_COSE_ALGORITHM_ES256),
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        check_alg_id, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 13. an integer content ID  */
    {
        UBX(x12), /* CBOR encoded header params */
        T_COSE_MAKE_CT_UINT_PARAM(42),
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        check_int_content_id, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 14. text string content ID  */
    {
        UBX(x13), /* CBOR encoded header params */
        T_COSE_MAKE_CT_TSTR_PARAM(UBS("text/plain")),
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        check_text_content_id, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 15. kid  */
    {
        UBX(x14), /* CBOR encoded header params */
        T_COSE_MAKE_KID_PARAM(UBS("this-is-a-kid")),
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        check_kid, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },


    /* 16. IV */
    {
        UBX(x15), /* CBOR encoded header params */
        T_COSE_MAKE_IV_PARAM(UBS("iviviviv")),
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        check_iv, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },

    /* 17. Partial IV */
    {
        UBX(x16), /* CBOR encoded header params */
        T_COSE_MAKE_PARTIAL_IV_PARAM(UBS("piv")),
        T_COSE_SUCCESS, /* Expected encode result */
        T_COSE_SUCCESS, /* Expected decode result */
        check_partial_iv, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },
    /* IV, PARTIAL IV */
#ifdef TODO_CRIT_PARAM_FIXED

    /* X. Critical parameter with no callback to handle it. */
    {
        UBX(x4), /* CBOR encoded header params */
        NULL,
        T_COSE_SUCCESS, /* Expected encode result */
        0, /* Expected decode result */
        NULL, /* Call back for decode check */
        QCBOR_SUCCESS /* Expected CBOR encode result */
    },
#endif


    /* */
    {
        {NULL, 0},
        {0, false, false, {0,0}, NO_ENCODE_TEST, .value.ptr = NULL},
        0,
        0,
        NULL,
        0
    }

};


struct param_test_combo {
    struct q_useful_buf_c  encoded;
    int                   *combo_list; // Index into param_tests. Terminated by MAX_INT
    enum t_cose_err_t      header_encode_result;
    QCBORError             qcbor_encode_result;
};

static struct param_test_combo param_combo_tests[] = {
    /* 0. Encode duplicate parameters */
    {
        UBX(x2),
        (int []){0, 0, INT_MAX},
        T_COSE_ERR_DUPLICATE_PARAMETER,
        QCBOR_SUCCESS,
    },
    /* 1. Several parameters success test */
    {
        UBX(x10),
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




int_fast32_t
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
    struct q_useful_buf_c           string;
    struct t_cose_parameter_storage param_storage;


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
        if(i == 7) {
            t_cose_result = 0;
        }

        /* Encode test */
        if(param_test->unencoded.value_type != NO_ENCODE_TEST) {
            QCBOREncode_Init(&qcbor_encoder, encode_buffer);
            t_cose_result = t_cose_encode_headers(&qcbor_encoder,
                                                  &(param_test->unencoded),
                                                  NULL);

            if(t_cose_result != param_test->encode_result) {
                return i * 1000 + 1;
            }

            if(t_cose_result == T_COSE_SUCCESS) {
                qcbor_result = QCBOREncode_Finish(&qcbor_encoder, &encoded_params);
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
            param_storage.size = sizeof(param_array)/sizeof(struct t_cose_parameter);
            param_storage.used = 0;
            param_storage.storage = param_array;
            struct t_cose_parameter *decoded_parameter;

            QCBORDecode_Init(&decode_context, param_test->encoded, 0);

            t_cose_result = t_cose_headers_decode(&decode_context,
                                                  (struct t_cose_header_location){0,0},
                                                  param_decoder, NULL,
                                                 &param_storage,
                                                 &decoded_parameter,
                                                 &encoded_prot_params);

            if(t_cose_result != param_test->decode_result) {
                return i * 1000 + 4;
            }

            if(t_cose_result == T_COSE_SUCCESS) {
                struct t_cose_parameter decoded = param_storage.storage[0];

                if(param_test->check_cb) {
                    int32_t r;
                    r = param_test->check_cb(&decoded);
                    if(r) {
                        return i * 1000 + 10 + r;
                    }
                } else {
                    if(decoded.value_type != param_test->unencoded.value_type) {
                        return i * 1000;
                    }
                    switch(decoded.value_type) {
                        case T_COSE_PARAMETER_TYPE_INT64:
                            if(decoded.value.i64 != param_test->unencoded.value.i64) {
                                return i * 1000 + 5;
                            }
                            break;

                        case T_COSE_PARAMETER_TYPE_TEXT_STRING:
                        case T_COSE_PARAMETER_TYPE_BYTE_STRING:
                            if(q_useful_buf_compare(decoded.value.string, param_test->unencoded.value.string)) {
                                return i * 1000 + 6;
                            }
                            break;
                    }
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
        t_cose_result = t_cose_encode_headers(&qcbor_encoder,
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



    /* One test that is not so data driven to test the encoding vector feature. */

    param_array[0] = param_tests[1].unencoded;

    param_array[1] = t_cose_make_ct_uint_parameter(42);
    param_array[0].next = &param_array[1];

    param_array[2] = t_cose_make_kid_parameter(Q_USEFUL_BUF_FROM_SZ_LITERAL("this-is-a-kid"));
    param_array[1].next = &param_array[2];

    param_array[3] = t_cose_make_iv_parameter(Q_USEFUL_BUF_FROM_SZ_LITERAL("iviviviv"));
    param_array[2].next = &param_array[3];

    param_array[4] = t_cose_make_partial_iv_parameter(Q_USEFUL_BUF_FROM_SZ_LITERAL("piv"));
    param_array[3].next = &param_array[4];

    param_array[5] = param_tests[0].unencoded;
    param_array[4].next = &param_array[5];

    param_array[6] = t_cose_make_alg_id_parameter(T_COSE_ALGORITHM_ES256);
    param_array[5].next = &param_array[6];


    QCBOREncode_Init(&qcbor_encoder, encode_buffer);
    t_cose_result = t_cose_encode_headers(&qcbor_encoder,
                                          &param_array[0],
                                          NULL);

    if(t_cose_result != T_COSE_SUCCESS) {
        return -1;
    }

    qcbor_result = QCBOREncode_Finish(&qcbor_encoder, &encoded_params);
    if(qcbor_result != QCBOR_SUCCESS) {
        return -2;
    }

    if(q_useful_buf_compare(encoded_params, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(x10))) {
        return -3;
    }


    if(t_cose_find_parameter_alg_id(NULL, true) != T_COSE_ALGORITHM_NONE) {
        return -4;
    }

#ifndef T_COSE_DISABLE_CONTENT_TYPE
    if(t_cose_find_parameter_content_type_int(NULL) != T_COSE_EMPTY_UINT_CONTENT_TYPE) {
        return -5;
    }
#endif


    if(!q_useful_buf_c_is_null(t_cose_find_parameter_kid(NULL))) {
        return -6;
    }

    if(!q_useful_buf_c_is_null(t_cose_find_parameter_iv(NULL))) {
        return -7;
    }

    if(!q_useful_buf_c_is_null(t_cose_find_parameter_partial_iv(NULL))) {
        return -8;
    }


    QCBORDecode_Init(&decode_context, encoded_params, 0);

    struct t_cose_parameter *dec;


    param_storage.size = sizeof(param_array)/sizeof(struct t_cose_parameter);
    param_storage.storage = param_array;
    param_storage.used = 0;


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
        return -10; //i * 1000 + 1;
    }

    if(t_cose_find_parameter_alg_id(dec, true) != T_COSE_ALGORITHM_ES256) {
        return -11;
    }

#ifndef T_COSE_DISABLE_CONTENT_TYPE
    if(t_cose_find_parameter_content_type_int (dec) != 42) {
        return -12;
    }
#endif


    string = t_cose_find_parameter_kid(dec);
    if(q_useful_buf_compare(string, Q_USEFUL_BUF_FROM_SZ_LITERAL("this-is-a-kid"))) {
        return -13;
    }

    string = t_cose_find_parameter_iv(dec);
    if(q_useful_buf_compare(string, Q_USEFUL_BUF_FROM_SZ_LITERAL("iviviviv"))) {
        return -14;
    }

    string = t_cose_find_parameter_partial_iv(dec);
    if(q_useful_buf_compare(string, Q_USEFUL_BUF_FROM_SZ_LITERAL("piv"))) {
        return -15;
    }

    /* Empty parameters section test */
    QCBOREncode_Init(&qcbor_encoder, encode_buffer);
    t_cose_result = t_cose_encode_headers(&qcbor_encoder,
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
            if(q_useful_buf_compare(encoded_params, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(x5))) {
                return -900;
            }
        }
    }

    param_storage.size = sizeof(param_array)/sizeof(struct t_cose_parameter);
    param_storage.used = 0;
    param_storage.storage = param_array;
    struct t_cose_parameter *decoded_parameter;

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

    return 0;
}
