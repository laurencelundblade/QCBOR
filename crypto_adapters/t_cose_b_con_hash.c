/*
 *  t_cose_b_con_hash.c
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md.
 *
 * Created 3/31/2019.
 */


#include "t_cose_crypto.h"

#include "t_cose_crypto.h"
#include "sha256.h"

#include <stdio.h>

SHA256_CTX s_context; /* not thread safe! */

/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t t_cose_crypto_hash_start(struct t_cose_crypto_hash *hash_ctx,
                                           int32_t cose_hash_alg_id)
{
    if(cose_hash_alg_id != COSE_ALG_SHA256_PROPRIETARY) {
        return T_COSE_ERR_UNSUPPORTED_HASH;
    }
    //printf("=== start hash  ===\n");
#if 1
    (void)hash_ctx; /* unused parameter */
    sha256_init(&s_context);
#else
    sha256_init(&(hash_ctx->context));
#endif
    return 0;
}

/*
 * See documentation in t_cose_crypto.h
 */
void t_cose_crypto_hash_update(struct t_cose_crypto_hash *hash_ctx,
                               struct q_useful_buf_c data_to_hash)
{
 
    
    if(data_to_hash.ptr) {
   /*     printf("[[");
        for(int i=0; i < data_to_hash.len; i++) {
            printf("%02x", ((uint8_t *)data_to_hash.ptr)[i]);
            if(0 && !((i+1)%8)) {
                printf("\n");
            }
        }
        printf("]]"); */
        
#if 1
        (void)hash_ctx; /* unused parameter */
        sha256_update(&s_context, data_to_hash.ptr, data_to_hash.len);
#else
        sha256_update(&(hash_ctx->context), data_to_hash.ptr, data_to_hash.len);
#endif
    }
}

/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hash_finish(struct t_cose_crypto_hash *hash_ctx,
                          struct q_useful_buf buffer_to_hold_result,
                          struct q_useful_buf_c *hash_result)
{
    //printf("\n=== finish hash  ===\n");

#if 1
    (void)hash_ctx; /* unused parameter */

    sha256_final(&s_context, buffer_to_hold_result.ptr);
#else
    sha256_final(&(hash_ctx->context), buffer_to_hold_result.ptr);
#endif
    *hash_result = (UsefulBufC){buffer_to_hold_result.ptr, 32};
    
/*         printf("[[");
     for(int i=0; i < hash_result->len; i++) {
     printf("%02x ", ((uint8_t *)hash_result->ptr)[i]);
     if(!((i+1)%8)) {
     printf("\n");
     }
     }
     printf("]]\n");*/
    
    return 0;
}
