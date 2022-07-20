//
//  t_cose_sign_verify.h
//  t_cose
//
//  Created by Laurence Lundblade on 7/17/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#ifndef t_cose_sign_verify_h
#define t_cose_sign_verify_h


/**
 * Context for signature verification.  It is about 56 bytes on a
 * 64-bit machine and 42 bytes on a 32-bit machine.
 */
struct t_cose_sign_verify_ctx {
    /* Private data structure */
    structure t_cose_signature_verify *verifiers;
    uint32_t              option_flags;
    uint64_t              auTags[T_COSE_MAX_TAGS_TO_RETURN];
};


/**
 * \brief Initialize for \c COSE_Sign1 message verification.
 *
 * \param[in,out]  context       The context to initialize.
 * \param[in]      option_flags  Options controlling the verification.
 *
 * This must be called before using the verification context.
 */
static void
t_cose_sign_verify_init(struct t_cose_sign_verify_ctx *context,
                        uint32_t                        option_flags);


t_cose_sign_add_verifier(struct t_cose_sign_verify_ctx *context)


/**
 * \brief Semi-private function to verify a COSE_Sign1.
 *
 * \param[in,out] me   The t_cose signature verification context.
 * \param[in] sign1         Pointer and length of CBOR encoded \c COSE_Sign1
 *                          message that is to be verified.
 * \param[in] aad           The Additional Authenticated Data or \c NULL_Q_USEFUL_BUF_C.
 * \param[in,out] payload   Pointer and length of the payload.
 * \param[out] parameters   Place to return parsed parameters. May be \c NULL.
 * \param[in] is_detached         Indicates the payload is detached.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * This does the work for t_cose_sign1_verify(),
 * t_cose_sign1_verify_aad() and t_cose_sign1_verify_detached(). It is
 * a semi-private function which means its interface isn't guaranteed
 * so it should not to call it directly.
 */
enum t_cose_err_t
t_cose_sign_verify(struct t_cose_sign_verify_ctx *me,
                             struct q_useful_buf_c           sign1,
                             struct q_useful_buf_c           aad,
                             struct q_useful_buf_c          *payload,
                             struct t_cose_parameters       *parameters,
                             bool                            is_detached);
#endif /* t_cose_sign_verify_h */
