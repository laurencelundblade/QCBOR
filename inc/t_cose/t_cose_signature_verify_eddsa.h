/*
 * t_cose_signature_verify_eddsa.h
 *
 * Copyright (c) 2022-2023, Laurence Lundblade. All rights reserved.
 * Created by Laurence Lundblade on 11/18/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef t_cose_signature_verify_eddsa_h
#define t_cose_signature_verify_eddsa_h

#include "t_cose/t_cose_signature_verify.h"
#include "t_cose_parameters.h"
#include "t_cose/t_cose_key.h"


#ifdef __cplusplus
extern "C" {
#endif


/**
 * Verification context.
 */
struct t_cose_signature_verify_eddsa {
    /* Private data structure */

    /* t_cose_signature_verify must be the first item for the
     * polymorphism to work.  This structure,
     * t_cose_signature_verify_eddsa, will sometimes be uses as a
     * t_cose_signature_verify.
     */
    struct t_cose_signature_verify  s;
    struct t_cose_key               verification_key;
    t_cose_param_special_decode_cb *special_param_decode_cb;
    void                           *special_param_decode_ctx;
    uint32_t                        option_flags;

    struct q_useful_buf_c           verification_kid;


    /**
     * A auxiliary buffer provided by the caller, used to serialize
     * the Sig_Structure. This is only needed when using EdDSA, as
     * otherwise the Sig_Structure is hashed incrementally.
     */
    struct q_useful_buf  auxiliary_buffer;

    /* The size of the serialized Sig_Structure used in the last
     * verification. This can be used by the user to determine a
     * suitable auxiliary buffer size.
     */
    size_t               auxiliary_buffer_size;

};


void
t_cose_signature_verify_eddsa_init(struct t_cose_signature_verify_eddsa *me,
                                   uint32_t                option_flags);


static void
t_cose_signature_verify_eddsa_set_key(struct t_cose_signature_verify_eddsa *me,
                                      struct t_cose_key verification_key,
                                      struct q_useful_buf_c verification_kid);

static void
t_cose_signature_verify_eddsa_set_special_param_decoder(struct t_cose_signature_verify_eddsa *me,
                                                t_cose_param_special_decode_cb               *decode_cb,
                                                void                                         *decode_ctx);

/**
 * \brief Configure a buffer used to serialize the Sig_Structure.
 *
 * \param[in,out] context       The t_cose signature verification context.
 * \param[in] auxiliary_buffer  The auxiliary buffer to be used.
 *
 * Some signature algorithms (namely EdDSA), require two passes over
 * their input. In order to achieve this, the library needs to serialize
 * a temporary to-be-signed structure into an auxiliary buffer. This function
 * allows the user to configure such a buffer.
 *
 * The buffer must be big enough to accomodate the Sig_Structure type,
 * which is roughly the sum of sizes of the encoded protected parameters,
 * aad and payload, along with a few dozen bytes of overhead.
 *
 * To compute the exact size needed, initialize the context with
 * the \ref T_COSE_OPT_DECODE_ONLY option, and call the
 * \ref t_cose_sign1_verify (or similar). After the message decoding,
 * the necessary auxiliary buffer size is available by calling
 * \ref t_cose_sign1_verify_auxiliary_buffer_size.
 *
 */
static void
t_cose_signature_verify_eddsa_set_auxiliary_buffer(struct t_cose_signature_verify_eddsa *context,
                                                   struct q_useful_buf             auxiliary_buffer);

/**
 * \brief Get the required auxiliary buffer size for the most recent
 * verification operation.
 *
 * \param[in,out] context       The t_cose signature verification context.
 *
 * \return The number of bytes of auxiliary buffer used by the most
 *         recent verification operation.
 *
 * This function can be called after \ref t_cose_sign1_verify (or
 * equivalent) was called. If the context was initialized with the
 * DECODE_ONLY flag, it returns the number of bytes that would have
 * been used by the signing operation. This allows the caller to
 * allocate an appropriately sized buffer before performing the
 * actual verification.
 *
 * This function returns zero if the signature algorithm used does not
 * need an auxiliary buffer.
 */
static size_t
t_cose_signature_verify_eddsa_auxiliary_buffer_size(struct t_cose_signature_verify_eddsa *context);


static struct t_cose_signature_verify *
t_cose_signature_verify_from_eddsa(struct t_cose_signature_verify_eddsa *context);




/* ------------------------------------------------------------------------
 * Private and inline implementations of public functions defined above.
 */

static inline void
t_cose_signature_verify_eddsa_set_key(struct t_cose_signature_verify_eddsa *me,
                                      struct t_cose_key verification_key,
                                      struct q_useful_buf_c verification_kid)
{
    me->verification_key = verification_key;
    me->verification_kid = verification_kid;
}

static inline void
t_cose_signature_verify_eddsa_set_special_param_decoder(struct t_cose_signature_verify_eddsa *me,
                                                        t_cose_param_special_decode_cb       *decode_cb,
                                                        void      *decode_ctx)
{
    me->special_param_decode_cb  = decode_cb;
    me->special_param_decode_ctx = decode_ctx;
}

static inline void
t_cose_signature_verify_eddsa_set_auxiliary_buffer(struct t_cose_signature_verify_eddsa *me,
                                        struct q_useful_buf auxiliary_buffer)
{
    me->auxiliary_buffer = auxiliary_buffer;

}

static inline size_t
t_cose_signature_verify_eddsa_auxiliary_buffer_size(struct t_cose_signature_verify_eddsa *me)
{
    return me->auxiliary_buffer_size;
}


static inline struct t_cose_signature_verify *
t_cose_signature_verify_from_eddsa(struct t_cose_signature_verify_eddsa *me)
{
    /* Because s is the first item in the t_cose_ecdsa_signer, this function should
     * compile to nothing. It is here to keep the type checking safe.
     */
    return &(me->s);
}


#ifdef __cplusplus
}
#endif

#endif /* t_cose_signature_verify_eddsa_h */
