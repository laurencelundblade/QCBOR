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
 * The reason signers are abstracted out as they are here is in
 * anticipation of more complicated signers that support things like
 * counter signing, post-quantum signatures and certificate
 * hierarchies.  A signer may support only one signing algorithm, but
 * that is not required. For examples the "main" signer supports
 * ECDSA and RSA because they are very similar. The EdDSA signer is
 * separate because it doesn't involve a hash. Counter signature are
 * too complicated to support with custom parameters so they should
 * implement a signer (need to validate the interface will work for
 * them).
 *
 * t_cose_signer_callback is the type of a function that every
 * signer must implement. It takes as input the context
 * for the particular signer, the hash to sign and
 * the encoder instance. The work it does is to produce
 * the signature and output the COSE_Signature to the
 * encoder instance.
 *
 * t_cose_signature_sign_h_callback is a callback that signers
 * that support COSE_Sign1 must implement in addition to
 * t_cose_signer_callback. It returns the
 * headers that have to go in the COSE_Sign1 body.
 *
 * This design allows new signers for new algorithms to be added
 * without modifying or even recompiling t_cose.  It is a
 * design that allows outputting a COSE_Sign that has multiple
 * signings by multiple aglorithms, for example an ECDSA signature and
 * an HSS/LMS signature.
 *
 * Because this design is based on dynamic linking it gives some help
 * dealing with code size and dependency on crypto libraries.  If you
 * don't call the init function for a signer or verifier it won't be
 * linked No disabling #define needed. You can just leave out the
 * source files for signers/verifiers you don't want and all will
 * compile and link nicely without having to managed a #define. (This
 * doesn't work to elimiate RSA if you use only ECDSA though because
 * they both go through the same layer in the crypto adaptation
 * layer. It does work for EdDSA).
 *
 * What's really going on here is a bit of doing object orientation
 * implementned in C. This is an abstract base class, an object that
 * has no implementation of it's own. Each signer type, e.g., the
 * main signer, inherits from this and provides an
 * implementation. The structure defined here holds the vtable for the
 * methods for the object. Only two methods happen to be needed. It's
 * called a "callback" here, but it could also be called the abstract
 * sign method.
 *
 * Since C doesn't support object orientation there's a few tricks to
 * make this fly. The concrete instantiation (e.g., the main signer)
 * must make struct t_cose_signature_sign is the first part of its
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
 * \brief Typedef of callback that  creates and outputs a bare signature in
 * a byte string for a COSE_Sign1.
 *
 * \param [in] me                    The context, the  t_cose_signature_sign
 *                                   instance.
 * \param[in] sign_inputs            Payload, aad and header parameters to sign.
 * \param[in] qcbor_encoder          The CBOR encoder context to ouput the
 *                                   simple byte string signature for a
 *                                   COSE_Sign1.
 *
 * This does the important work of computing the hash of the inputs
 * and invoking the public key signing algorithm. It then outputs a
 * byte string with signature to \c qcbor_encoder.
 */
typedef enum t_cose_err_t
t_cose_signature_sign1_cb(struct t_cose_signature_sign    *me,
                          const struct t_cose_sign_inputs *sign_inputs,
                          QCBOREncodeContext              *qcbor_encoder);


/**
 * \brief Typedef of callback that  signs and encodes a COSE_Signature.
 *
 * \param [in] me                    The context, the  t_cose_signature_sign
 *                                   instance. This will actually be some
 *                                   thing like t_cose_signature_sign_main
 *                                   that implements t_cose_signature_sign
 * \param[in] sign_inputs            Payload, aad and header parameters to sign.
 * \param[in] qcbor_encoder          The CBOR encoder context to ouput
 *                                   a COSE_Signature.
 *
 * Implementers of t_cose_signature_sign must implement one of
 * these. It is the method used to perform the cryptographic signing
 * operation and to output either a bare signature for a COSE_Sign1 or
 * a full COSE_Signature for a COSE_Sign
 *
 * If the output buffer in qcbor_encoder is NULL, then this must just
 * compute the size and add the size to qcbor_encoder because it is
 * being called in size calculation mode.
 *
 * If a signer implements only COSE_SIgn1, this still should be
 * implemented and it should return an error.
 *
 * Note that \c sign_inputs is not const because it will be modifed to fill
 * in the sign-protected headers.
 */
typedef enum t_cose_err_t
t_cose_signature_sign_cb(struct t_cose_signature_sign  *me,
                         struct t_cose_sign_inputs     *sign_inputs,
                         QCBOREncodeContext            *qcbor_encoder);


/**
 * \brief Typedef of callback to get body header params for COSE_Sign1.
 *
 * \param [in] me             The context, the  t_cose_signature_sign
 *                            instance. This  will actully be some thing like
 *                            t_cose_signature_sign_main that implements
 *                            t_cose_signature_sign.
 * \param[out] header_params  Linked list of header parameters to be encoded
 *                            and added to the body header params.
 *
 * Usually there are no errors in this because it does very little. If
 * there is an error here that needs to be returned, set it in the
 * instance context and then return it when
 * t_cose_signature_sign_callback is
 * called. t_cose_signature_sign_callback is always called (the point
 * of not returning an error here is to save object code).
 *
 * This is never called for COSE_Sign.
*/
typedef void
t_cose_signature_sign_headers_cb(struct t_cose_signature_sign *me,
                                 struct t_cose_parameter     **header_params);


/**
 * Data structture that must be the first part of every context of
 * every concrete implementation of t_cose_signature_sign. The
 * function callback pointers should never be NULL, but they may be
 * stubs that return an error when the callback is not implemented.
 */
struct t_cose_signature_sign {
    struct t_cose_rs_obj             rs;
    t_cose_signature_sign_headers_cb *headers_cb;
    t_cose_signature_sign_cb         *sign_cb;
    t_cose_signature_sign1_cb        *sign1_cb;
};


#endif /* t_cose_signer_h */
