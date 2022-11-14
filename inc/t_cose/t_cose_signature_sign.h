/*
 * t_cose_signature_sign.h
 *
 * Copyright (c) 2022, Laurence Lundblade. All rights reserved.
 * Created by Laurence Lundblade on 5/23/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef t_cose_signer_h
#define t_cose_signer_h

#include "qcbor/qcbor_encode.h"
#include "t_cose/t_cose_parameters.h"


/* This is an "abstract base class" for all signers
 * of all types for all algorithms. This is the interface
 * and data structure that t_cose_sign_sign knows about to be able
 * to invoke each signer regardles of its type or algorithm.
 *
 * Each concrete signer must implement this. Each signer
 * also implements a few methods of its own beyond this
 * that it needs to work like those for initialization and
 * setting the key.
 *
 * Typically a signer will support one suite of algorithms,
 * but there is no requirement that this be so. It is OK
 * for a signer to implement several algorithms. The reason
 * signers are abstracted out as they are here is in anticipation
 * of more complicated signers that support things like counter
 * signing, post-quantum signatures and certificate hierarchies.
 *
 * t_cose_signer_callback is the type of a function that every
 * signer must implement. It takes as input the context
 * for the particular signer, the hash to sign and
 * the encoder instance. The work it does is to produce
 * the signature and output the COSE_Signature to the
 * encoder instance.
 *
 * t_cose_signature_sign_h_callback is a callback that signers
 * that support COSE_Sign1 must implement. It returns the
 * headers that have to go in the COSE_Sign1 body.
 *
 * This design allows new signers for new algorithms to be added
 * without modifying or even recompiling t_cose.  It is a clean and
 * simple design that allows outputting a COSE_Sign that has multiple
 * signings by multiple aglorithms, for example an ECDSA signature and
 * an HSS/LMS signature.
 *
 * What's really going on here is a bit of doing object orientation
 * implementned in C. This is an abstract base class, an object that
 * has no implementation of it's own. Each signer type, e.g., the
 * ECDSA signer, inherits from this and provides an
 * implementation. The structure defined here holds the vtable for the
 * methods for the object. Only one method happens to be needed. It's
 * called a "callback" here, but it could also be called the abstract
 * sign method.
 *
 * Since C doesn't support object orientation there's a few tricks to
 * make this fly. The concrete instantiation (e.g., an ECDSA signer)
 * must make struct t_cose_signature_sign the first part of its
 * context and there will be casts back and forth between this
 * abstraction and the real instantion of the signer. The other trick
 * is that struct here contains a pointer to a function and that makes
 * up the vtable, something that C++ would do for you.
 */

/* A declaration (not definition) of the generic structure for a signer.
 * See https://stackoverflow.com/questions/888386/resolve-circular-typedef-dependency
 */
struct t_cose_signature_sign;


/**
 * \brief Typedef of callback that makes a COSE_Signature.
 *
 * \param [in] me                    The context, the  t_cose_signature_sign
 *                                   instance. This will actuzlly be some
 *                                   thing like t_cose_signature_sign_ecdsa
 *                                   that inplements t_cose_signature_sign
 * \Param[in] make_cose_signature    If true output a full COSE_Signature. If
 *                                   false output the bare signature for a
 *                                   COSE_Sign1.
 * \param[in] protected_body_headers The COSE_Sign body headers covered by the
 *                                   signature
 * \param[in] payload                The payload (regular or detached) that
 *                                   is covered by the signature.
 * \param[in] aad                    The aad covered by the signature.
 * \param[in] qcbor_encoder          The CBOR encoder context to ouput either
 *                                   a COSE_Signature or the simple byte
 *                                   string signature for a COSE_Sign1.
 *
 * Implementers of t_cose_signature_sign must implement one of
 * these. It is the method used to perform the cryptographic signing
 * operation and to output either a bare signature for a COSE_Sign1 or
 * a full COSE_Signature for a COSE_Sign
 *
 * If the output buffer in qcbor_encoder is NULL, then this must just
 * compute the size and add the size to qcbor_encoder because it is
 * being called in size calculation mode.
 */
typedef enum t_cose_err_t
t_cose_signature_sign_callback(struct t_cose_signature_sign *me,
                               bool                        make_cose_signature,
                               const struct q_useful_buf_c   protected_body_headers,
                               const struct q_useful_buf_c   payload,
                               const struct q_useful_buf_c   aad,
                               QCBOREncodeContext           *qcbor_encoder);


/**
 * \brief Typedef of callback to get body header params for COSE_Sign1.
 *
 * \param [in] me             The context, the  t_cose_signature_sign
 *                            instance. This  will actully be some thing like
 *                            t_cose_signature_sign_ecdsa that inplements
 *                            t_cose_signature_sign.
 * \param[out] header_params  Linked list of header parameters to be encoded
 *                            and added to the body header params.
 *
 * Usually there are no errors in this because it does very little. If
 * there is an error here that needs to be returned, set it in the
 * instance context and then return it when
 * t_cose_signature_sign_callback is
 * called. t_cose_signature_sign_callback is always called. (The point
 * of not returning an error here is to save object code)
 *
 * This is never called for COSE_Sign.
*/
typedef void
t_cose_signature_sign_h_callback(struct t_cose_signature_sign *me,
                                 struct t_cose_parameter     **header_params);


/**
 * Data structture that must be the first part of every context of every concrete
 * implementation of t_cose_signature_sign.
 */
struct t_cose_signature_sign {
    /* some will call this a vtable with two entries */
    t_cose_signature_sign_callback   *callback;
    t_cose_signature_sign_h_callback *h_callback;
    struct t_cose_signature_sign     *next_in_list; /* linked list of signers */
};


#endif /* t_cose_signer_h */
