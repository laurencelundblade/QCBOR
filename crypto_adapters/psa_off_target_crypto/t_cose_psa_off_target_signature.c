/*
 psa_off_target_signature.c

 Copyright 2018, Laurence Lundblade

 Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice, this
 list of conditions and the following disclaimer in the documentation and/or other
 materials provided with the distribution.

 3. Neither the name of the copyright holder nor the names of its contributors may
 be used to endorse or promote products derived from this software without specific
 prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 OF SUCH DAMAGE.
 */
#include "psa_crypto.h"
#include <string.h>
#include "t_cose_defines.h"



// openssl headers
#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h" // for NID for EC curve

psa_status_t psa_asymmetric_sign_old(psa_key_handle_t key,
                                 psa_algorithm_t alg,
                                 const uint8_t *hash,
                                 size_t hash_length,
                                 uint8_t *signature,
                                 size_t signature_size,
                                 size_t *signature_length)
{
    (void)key; /* unused variable */
    (void)alg; /* unused variable */
    (void)hash; /* unused variable */
    (void)hash_length; /* unused variable */
    (void)signature; /* unused variable */
    (void)signature_size; /* unused variable */
    (void)signature_length; /* unused variable */

    memcpy(signature, "xxxxxxxxxxyyyyyyyyyzzzzzzzzzz__xxxxxxxxxxyyyyyyyyyyzzzzzzzzzz__", 64);
    *signature_length = 64;
    return 0;
}


psa_status_t psa_asymmetric_sign(psa_key_handle_t key,
                                 psa_algorithm_t alg,
                                 const uint8_t *hash,
                                 size_t hash_length,
                                 uint8_t *signature,
                                 size_t signature_size,
                                 size_t *signature_length)
{
    (void)key; /* unused variable */
    (void)alg;
    (void)signature_size;
    
    goto XXX;

 /*   if(alg != COSE_ALGORITHM_ES256) {
        return -999; // not the only algorithm supported
    } */

    
    ECDSA_SIG *sig;
    EC_KEY *eckey = NULL;
    const BIGNUM *r, *s;
    
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    
    sig = ECDSA_do_sign(hash, (int)hash_length, eckey);
    if(sig == NULL) {
        return -11;
    }
    
    ECDSA_SIG_get0(sig, &r, &s);
    
    int x = BN_num_bytes(r);
    BN_bn2bin(r, signature);
    BN_bn2bin(s, signature+x);
    // TODO: check that both fit in signature
    // TODO: check that this is the correct formatting of the signature
    //BN_free(r);
    //BN_free(s);

XXX:
    memcpy(signature, "xxxxxxxxxxyyyyyyyyyzzzzzzzzzz__xxxxxxxxxxyyyyyyyyyyzzzzzzzzzz__", 64);
    *signature_length = 64;
    return 0;
}

