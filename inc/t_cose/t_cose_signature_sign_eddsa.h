/*
 * t_cose_signature_sign_eddsa.h
 *
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 * Created by Laurence Lundblade on 11/15/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef t_cose_eddsa_signer_h
#define t_cose_eddsa_signer_h

#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose/t_cose_key.h"

#ifdef __cplusplus
extern "C" {
#endif


struct t_cose_signature_sign_eddsa {
    /* Private data structure */

    /* t_cose_signer must be the first item for the polymorphism to
     * work.  This structure, t_cose_ecdsa_signer, will sometimes be
     * uses as a t_cose_signer.
     */
    struct t_cose_signature_sign s;

    /* The rest of this is mostly specific to EDDSA signing */
    struct q_useful_buf_c        kid;
    struct t_cose_key            signing_key;
    uint32_t                     option_flags; // TODO: use or get rid of
    struct t_cose_parameter      local_params[2];
    struct t_cose_parameter     *added_signer_params;

    /**
     * A auxiliary buffer provided by the caller, used to serialize
     * the Sig_Structure. This is only needed when using EdDSA, as
     * otherwise the Sig_Structure is hashed incrementally.
     */
    struct q_useful_buf  auxiliary_buffer;

    /* The size of the serialized Sig_Structure used in the last
     * signing operation. This can be used by the user to determine
     * a suitable auxiliary buffer size.
     */
    size_t               auxiliary_buffer_size;
};


/*
 *
 *
 * This signer supports the ECDSA algorithms PS256, PS384 and PS512. */
void
t_cose_signature_sign_eddsa_init(struct t_cose_signature_sign_eddsa *context);


/*
 * Set the signing key and kid. The kid may be NULL_Q_USEFUL_BUF_C.
 */
static void
t_cose_signature_sign_eddsa_set_signing_key(struct t_cose_signature_sign_eddsa *context,
                                            struct t_cose_key       signing_key,
                                            struct q_useful_buf_c   kid);


/* The header parameter for the algorithm ID is generated automatically.
   and should not be added in this list.

 This is for the header parameters that go in the COSE_Signature. See
 t_cose_sign_add_body_header_parameters() for the parameters that go in
 the COSE_Sign and COSE_Sign1 main body.

 The parameters to add are passed in as an array of
 t_cose_header_param.  Note that individual parameters in this array
 can have a call back that does the encoding, so it is possible to
 handle complicated parameters, such as ones that are maps and arrays
 themselves.
 */
static void
t_cose_signature_sign_eddsa_set_header_parameter(struct t_cose_signature_sign_eddsa *context,
                                                 struct t_cose_parameter   *header_parameters);



/**
 * \brief Configure an auxiliary buffer used to serialize the Sig_Structure.
 *
 * \param[in] context           The t_cose signing context.
 * \param[in] auxiliary_buffer  The buffer used to serialize the Sig_Structure.
 *
 * Some signature algorithms (namely EdDSA), require two passes over
 * their input. In order to achieve this, the library needs to serialize
 * a temporary to-be-signed structure into an auxiliary buffer. This function
 * allows the user to configure such a buffer.
 *
 * The buffer must be big enough to accomodate the Sig_Structure type,
 * which is roughly the sum of sizes of the encoded protected parameters, aad
 * and payload, along with a few dozen bytes of overhead.
 *
 * To compute the exact size needed, an auxiliary buffer with a NULL
 * pointer and a large size, such as \c UINT32_MAX, can be used. No
 * actual signing will take place, but the auxiliary buffer will be shrunk
 * to the to expected size.
 *
 */
static void
t_cose_signature_sign_eddsa_set_auxiliary_buffer(struct t_cose_signature_sign_eddsa *context,
                                        struct q_useful_buf auxiliary_buffer);

/**
 * \brief Get the required auxiliary buffer size for the most recent
 * signing operation.
 *
 * \param[in] context           The t_cose signing context.
 *
 * \return The number of bytes of auxiliary buffer used by the most
 *         recent signing operation.
 *
 * This function can be called after \ref t_cose_sign1_sign (or
 * equivalent) was called. If a NULL output buffer was passed to the
 * signing function (to operate in size calculation mode), this returns
 * the number of bytes that would have been used by the signing
 * operation. This allows the caller to allocate an appropriately sized
 * buffer before performing the actual verification.
 *
 * This function returns if the signature algorithm used does not need
 * an auxiliary buffer.
 */
static size_t
t_cose_signature_sign_eddsa_auxiliary_buffer_size(struct t_cose_signature_sign_eddsa *context);


/* This is how you get the general interface / instance for a signer,
 * a t_cose_signer, from the specific and concrete instance of a
 * signer. Because the t_cose_signer is the first member in a
 * t_cose_ecdsa_signer, the implementation for this is in essence just
 * a cast and in the end no code is generated.
 *
 * t_cose calls signers as follows:
 *   struct t_cose_signature_sign *signer;
 *   signer = t_cose_signature_sign_from_eddsa(me);
 *
 *   result = (signer->s.callback)(signer, ....);
 *
 * It makes use of the function pointer in signer->s. This callback is
 * where all the interesting work is done by
 * t_cose_signature_sign_eddsa.
 *
 */
static struct t_cose_signature_sign *
t_cose_signature_sign_from_eddsa(struct t_cose_signature_sign_eddsa *me);



/* =========================================================================
 BEGINNING OF PRIVATE INLINE IMPLEMENTATION
 ========================================================================= */

static inline void
t_cose_signature_sign_eddsa_set_signing_key(struct t_cose_signature_sign_eddsa *me,
                                            struct t_cose_key       signing_key,
                                            struct q_useful_buf_c   kid)
{
    me->signing_key = signing_key;
    me->kid         = kid;
    me->auxiliary_buffer.len = SIZE_MAX;
}



static inline struct t_cose_signature_sign *
t_cose_signature_sign_from_eddsa(struct t_cose_signature_sign_eddsa *me)
{
    /* Because s is the first item in the t_cose_ecdsa_signer, this
     * function should compile to nothing. It is here to keep the type
     * checking safe.
     */
    return &(me->s);
}


static inline void
t_cose_signature_sign_eddsa_set_header_parameter(struct t_cose_signature_sign_eddsa *me,
                                                 struct t_cose_parameter *header_parameters)
{
    me->added_signer_params = header_parameters;
}


static inline void
t_cose_signature_sign_eddsa_set_auxiliary_buffer(struct t_cose_signature_sign_eddsa *me,
                                          struct q_useful_buf auxiliary_buffer)
{
    me->auxiliary_buffer = auxiliary_buffer;
}


static inline size_t
t_cose_signature_sign_eddsa_auxiliary_buffer_size(struct t_cose_signature_sign_eddsa *me)
{
    return me->auxiliary_buffer_size;
}


#ifdef __cplusplus
}
#endif

#endif /* t_cose_eddsa_signer_h */
