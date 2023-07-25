/*
 * t_cose_standard_constants.h
 *
 * Copyright (c) 2018-2023, Laurence Lundblade. All rights reserved.
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_STANDARD_CONSTANTS_H__
#define __T_COSE_STANDARD_CONSTANTS_H__

/**
 * \file t_cose_standard_constants.h
 *
 * \brief Constants from COSE standard and IANA registry.
 *
 * This file contains constants identifiers defined in
 * [COSE (RFC 8152)](https://tools.ietf.org/html/rfc8152) and
 * [IANA COSE Registry](https://www.iana.org/assignments/cose/cose.xhtml).
 * They include algorithm IDs and other constants.
 *
 * Many constants in the IANA registry are not included here yet as
 * they are not needed by t_cose. They can be added if they become
 * needed.
 *
 * TODO: now that this is public....
 * This file is not part of the t_cose public interface as it contains
 * lots of stuff not needed in the public interface. The parts that
 * are needed in the public interface are also defined as \ref
 * T_COSE_ALGORITHM_ES256 and related (there is a pre processor cross
 * check to make sure they don't get defined differently in
 * t_cose_sign1_sign.c).
 */


/* --------------- COSE Header parameters -----------
 * https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
 */

/**
 * \def T_COSE_HEADER_PARAM_ALG
 *
 * \brief Label of COSE parameter that indicates an algorithm.
 *
 * The algorithm assignments are found in the IANA registry here
 * https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 * Signing algorithms are identified as combinations of the
 * public key algorithm, padding mode and hash. This must be
 * a protected header. They may be string or integers. This
 * implementation only support integer IDs.
 */
#define T_COSE_HEADER_PARAM_ALG 1


/**
 * \def T_COSE_HEADER_PARAM_CRIT
 *
 * \brief Label of COSE parameter listing critical header parameters
 *
 * The contents is an array of header parameter labels, either string or
 * integer. The implementation must know how to process them or it is
 * an error.
 */
#define T_COSE_HEADER_PARAM_CRIT 2


/**
 * \def T_COSE_HEADER_PARAM_CONTENT_TYPE
 *
 * \brief Label of COSE parameter with the content type
 *
 * Either an integer CoAP content type or a string MIME type. This is
 * the type of the data in the payload.
 */
#define T_COSE_HEADER_PARAM_CONTENT_TYPE 3


/**
 * \def T_COSE_HEADER_PARAM_KID
 *
 * \brief CBOR map label of COSE parameter that contains a kid (key ID).
 *
 * The kid is a byte string identifying the key. It is optional and
 * there is no required format. They are not even required to be
 * unique.
 */
#define T_COSE_HEADER_PARAM_KID 4


/**
 * \def T_COSE_HEADER_PARAM_IV
 *
 * \brief CBOR map label of parameter that contains an initialization
 * vector.
 *
 * A binary string initialization vector.
 *
 * This implementation only parses this.
 */
#define T_COSE_HEADER_PARAM_IV 5


/**
 * \def T_COSE_HEADER_PARAM_PARTIAL_IV
 *
 * \brief CBOR map label of parameter containing partial
 * initialization vector.
 *
 * A binary string partial initialization vector.
 *
 * This implementation only parses this.
 */
#define T_COSE_HEADER_PARAM_PARTIAL_IV 6


/**
 * \def T_COSE_HEADER_PARAM_COUNTER_SIGNATURE
 *
 * \brief CBOR map label of parameter that holds one or more counter signature.
 *
 * Counter signatures can be full \c COSE_Sign1, \c COSE_Signature and
 * such messages.  This implementation doesn't support them.
 */
#define T_COSE_HEADER_PARAM_COUNTER_SIGNATURE 7





/* ------------ COSE Header Algorithm Parameters --------------
 * https://www.iana.org/assignments/cose/cose.xhtml#header-algorithm-parameters
 */

/**
 * \def T_COSE_HEADER_ALG_PARAM_HPKE_SENDER_INFO
 *
 * \brief CBOR label of header algorithm parameter containing
 *        the HPKE_sender_info structure.
 *
 * This implementation only supports a subset of the available algorithms.
 */
#define T_COSE_HEADER_ALG_PARAM_HPKE_SENDER_INFO -4


/**
 * \def T_COSE_HEADER_ALG_PARAM_EPHEMERAL_KEY
 *
 * \brief Label of COSE header algorithm parameter that indicates an ephemeral key.
 *
 */
#define T_COSE_HEADER_ALG_PARAM_EPHEMERAL_KEY -1

#define T_COSE_HEADER_ALG_PARAM_SALT -20


#define T_COSE_HEADER_ALG_PARAM_PARTYU_IDENT -21
#define T_COSE_HEADER_ALG_PARAM_PARTYV_IDENT -24



/* ------------- COSE Algorithms ----------------------------
 * https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */

/**
 * This is defined as reserved by IANA. This implementation uses it to
 * mean the end of a list of algorithm IDs or an unset algorithm ID.
 */
#define T_COSE_ALGORITHM_RESERVED 0


/**
 * \def T_COSE_ALGORITHM_HPKE_v1_BASE
 *
 * \brief Indicates use of HPKE in base mode (version 1).
 *
 * Value for \ref T_COSE_HEADER_PARAM_ALG to indicate HPKE usage.
 *
 * The HPKE functionality for COSE is specified in draft-ietf-cose-hpke.
 *
 * See https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke
 */
#define T_COSE_ALGORITHM_HPKE_v1_BASE  -1

/**
 * \def T_COSE_ALGORITHM_ES256
 *
 * \brief Indicates ECDSA with SHA-256.
 *
 * Value for \ref T_COSE_HEADER_PARAM_ALG to indicate ECDSA with SHA-256.
 *
 * RFC 8152 section 8.1 suggests, but does not require, that this
 * algorithm identifier only be used with keys based on the P-256
 * curve (also known as prime256v1 or secp256r1).
 *
 * See https://tools.ietf.org/search/rfc4492 and https://tools.ietf.org/html/rfc8152
 */
#define T_COSE_ALGORITHM_ES256 -7

/**
 * \def COSE_ALGORITHM_EDDSA
 *
 * \brief Indicates EDDSA.
 *
 * Value for \ref COSE_HEADER_PARAM_ALG to indicate EDDSA.
 *
 * Keys using either the edwards25519 or edwards448 curves can be used
 * with this algorithm.
 *
 * See https://tools.ietf.org/search/rfc8032 and https://tools.ietf.org/html/rfc8152
 */
#define T_COSE_ALGORITHM_EDDSA -8

/**
 * \def COSE_ALGORITHM_ES384
 *
 * \brief Indicates ECDSA with SHA-384.
 *
 * See discussion on \ref T_COSE_ALGORITHM_ES256.
 *
 * RFC 8152 section 8.1 suggests, but does not require, that this
 * algorithm identifier be used only with keys based on the P-384
 * curve (also known as secp384r1).
 */
#define T_COSE_ALGORITHM_ES384 -35

/**
 * \def T_COSE_ALGORITHM_ES512
 *
 * \brief Indicates ECDSA with SHA-512.
 *
 * See discussion on \ref T_COSE_ALGORITHM_ES256.
 *
 * RFC 8152 section 8.1 suggests, but does not require, that this
 * algorithm identifier be used only with keys based on the P-521
 * curve (also known as secp521r1)
 */
#define T_COSE_ALGORITHM_ES512 -36

/**
 * \def COSE_ALGORITHM_PS256
 *
 * \brief Indicates RSASSA-PSS with SHA-256.
 *
 * Value for \ref COSE_HEADER_PARAM_ALG to indicate RSASSA-PSS with SHA-256.
 *
 * See https://tools.ietf.org/search/rfc8230 and https://tools.ietf.org/html/rfc8152
 */
#define T_COSE_ALGORITHM_PS256 -37

/**
 * \def COSE_ALGORITHM_PS384
 *
 * \brief Indicates RSASSA-PSS with SHA-384.
 *
 * Value for \ref COSE_HEADER_PARAM_ALG to indicate RSASSA-PSS with SHA-384.
 *
 * See https://tools.ietf.org/search/rfc8230 and https://tools.ietf.org/html/rfc8152
 */
#define T_COSE_ALGORITHM_PS384 -38

/**
 * \def COSE_ALGORITHM_PS512
 *
 * \brief Indicates RSASSA-PSS with SHA-512.
 *
 * Value for \ref COSE_HEADER_PARAM_ALG to indicate RSASSA-PSS with SHA-512.
 *
 * See https://tools.ietf.org/search/rfc8230 and https://tools.ietf.org/html/rfc8152
 */
#define T_COSE_ALGORITHM_PS512 -39

/**
 * \def T_COSE_ALGORITHM_SHA_256
 *
 * \brief Indicates simple SHA-256 hash.
 *
 * This is not used in the t_cose interface, just used internally.
 */
#define T_COSE_ALGORITHM_SHA_256 -16

/**
 * \def T_COSE_ALGORITHM_SHA_384
 *
 * \brief Indicates simple SHA-384 hash.
 *
 * This is not used in the t_cose interface, just used internally.
 */
#define T_COSE_ALGORITHM_SHA_384 -43

/**
 * \def T_COSE_ALGORITHM_SHA_512
 *
 * \brief Indicates simple SHA-512 hash.
 *
 * This is not used in the t_cose interface, just used internally.
 */
#define T_COSE_ALGORITHM_SHA_512 -44


/**
 * \def T_COSE_ALGORITHM_ECDH_ES_A256KW
 *
 * \brief ECDH ES w/ Concat KDF and AES Key Wrap w/ 256-bit key
 */
#define T_COSE_ALGORITHM_ECDH_ES_A256KW -31

/**
 * \def T_COSE_ALGORITHM_ECDH_ES_A192KW
 *
 * \brief ECDH ES w/ Concat KDF and AES Key Wrap w/ 192-bit key
 */
#define T_COSE_ALGORITHM_ECDH_ES_A192KW -30

/**
 * \def T_COSE_ALGORITHM_ECDH_ES_A128KW
 *
 * \brief ECDH ES w/ Concat KDF and AES Key Wrap w/ 128-bit key
 */
#define T_COSE_ALGORITHM_ECDH_ES_A128KW -29

/**
 * \def COSE_ALGORITHM_A256KW
 *
 * \brief AES Key Wrap w/ 256-bit key
 */
#define T_COSE_ALGORITHM_A256KW -5

/**
 * \def COSE_ALGORITHM_A192KW
 *
 * \brief AES Key Wrap w/ 192-bit key
 */
#define T_COSE_ALGORITHM_A192KW -4

 /**
 * \def COSE_ALGORITHM_A128KW
 *
 * \brief AES Key Wrap w/ 128-bit key
 */
#define T_COSE_ALGORITHM_A128KW -3

/**
 * \def COSE_ALGORITHM_A128GCM
 *
 * \brief AES-GCM mode w/ 128-bit key, 128-bit tag
 */
#define T_COSE_ALGORITHM_A128GCM 1

/**
 * \def COSE_ALGORITHM_A192GCM
 *
 * \brief AES-GCM mode w/ 192-bit key, 128-bit tag
 *
 * Note that while RFC 9180 (HPKE) doesn't define
 * support of this, RFC 9053 (COSE) for direct
 * and key wrap encryption.
 */
#define T_COSE_ALGORITHM_A192GCM 2

/**
 * \def COSE_ALGORITHM_A256GCM
 *
 * \brief AES-GCM mode w/ 256-bit key, 128-bit tag
 */
#define T_COSE_ALGORITHM_A256GCM 3

/**
 * \def COSE_ALGORITHM_AES128CCM_16_128
 *
 * \brief AES-CCM mode 128-bit key, 128-bit tag, 13-byte nonce
 */
#define T_COSE_ALGORITHM_AES128CCM_16_128 30

/**
 * \def COSE_ALGORITHM_AES256CCM_16_128
 *
 * \brief AES-CCM mode 256-bit key, 128-bit tag, 13-byte nonce
 */
#define T_COSE_ALGORITHM_AES256CCM_16_128 31

/**
 * \def T_COSE_ALGORITHM_HMAC256
 *
 * \brief Indicates HMAC with SHA256
 *
 * This value comes from the
 * [IANA COSE Registry](https://www.iana.org/assignments/cose/cose.xhtml).
 *
 * Value for \ref T_COSE_HEADER_PARAM_ALG to indicate HMAC w/ SHA-256
 */
#define T_COSE_ALGORITHM_HMAC256 5

/**
 * \def T_COSE_ALGORITHM_HMAC384
 *
 * \brief Indicates HMAC with SHA384
 *
 * This value comes from the
 * [IANA COSE Registry](https://www.iana.org/assignments/cose/cose.xhtml).
 *
 * Value for \ref T_COSE_HEADER_PARAM_ALG to indicate HMAC w/ SHA-384
 */
#define T_COSE_ALGORITHM_HMAC384 6

/**
 * \def T_COSE_ALGORITHM_HMAC512
 *
 * \brief Indicates HMAC with SHA512
 *
 * This value comes from the
 * [IANA COSE Registry](https://www.iana.org/assignments/cose/cose.xhtml).
 *
 * Value for \ref T_COSE_HEADER_PARAM_ALG to indicate HMAC w/ SHA-512
 */
#define T_COSE_ALGORITHM_HMAC512 7


/**
 * \def T_COSE_ALGORITHM_SHORT_CIRCUIT_256
 *
 * \brief Special algorithm ID for test only
 *
 * This selects an algorithm that simulates an ECDSA signature.
 * It is mplemented only by the test crypto adaptor. It has
 * no security value, but is useful for testing and bringing
 * t_cose up on a new target.
 * The actual value is randomly selected from the COSE
 * private ID space. It is not registered anywhere.
 */
// TODO: reference to details of short-circuit signature.
#define T_COSE_ALGORITHM_SHORT_CIRCUIT_256 -1000256
#define T_COSE_ALGORITHM_SHORT_CIRCUIT_384 -1000384
#define T_COSE_ALGORITHM_SHORT_CIRCUIT_512 -1000512

/**
 * \def T_COSE_ALGORITHM_NONE
 *
 * \brief Indicate no algorithm
 *
 * This can mean unset, or error or such.  This is a reserved
 * value per the COSE standard and can never be assigned.
 */
#define T_COSE_ALGORITHM_NONE 0




/* ---------- COSE Key Common Parameters --------------
 * https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
 */

/**
 * \def T_COSE_KEY_COMMON_KTY
 *
 * \brief Label for data item containing the key type.
 *
 * In a \c COSE_Key, label that indicates the data item containing the
 * key type.
 */
#define T_COSE_KEY_COMMON_KTY  1

/**
 * \def T_COSE_KEY_COMMON_KID
 *
 * \brief Label for data item containing the key's kid.
 *
 * In a \c COSE_Key, label that indicates the data item containing the
 * kid of this key.
 */
#define T_COSE_KEY_COMMON_KID  2




/* ---------- COSE Key Type Parameters --------------------
 * https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
 *
 * These are not used by this implementation.
 */

/**
 * \def T_COSE_KEY_PARAM_CRV
 *
 * \brief Label for data item indicating EC curve.
 *
 * In a \c COSE_Key that holds an EC key of either type \ref
 * T_COSE_KEY_TYPE_EC2 or \ref T_COSE_KEY_TYPE_OKP this labels the data
 * item with the EC curve for the key.
 */
#define T_COSE_KEY_PARAM_CRV           -1

/**
 * \def T_COSE_KEY_PARAM_X_COORDINATE
 *
 * \brief Label for data item that is an X coordinate of an EC key.
 *
 * In a \c COSE_Key that holds an EC key, this is label that indicates
 * the data item containing the X coordinate.
 *
 * This is used for both key types \ref T_COSE_KEY_TYPE_EC2 and \ref
 * T_COSE_KEY_TYPE_OKP.
 */
#define T_COSE_KEY_PARAM_X_COORDINATE  -2

/**
 * \def T_COSE_KEY_PARAM_Y_COORDINATE
 *
 * \brief Label for data item that is a y coordinate of an EC key.
 *
 * In a COSE_Key that holds an EC key, this is label that indicates
 * the data item containing the Y coordinate.
 *
 * This is used only for key type \ref T_COSE_KEY_TYPE_EC2.
 */
#define T_COSE_KEY_PARAM_Y_COORDINATE  -3

/**
 * \def T_COSE_KEY_PARAM_PRIVATE_D
 *
 * \brief Label for data item that is d, the private part of EC key.
 *
 * In a \c COSE_Key that holds an EC key, this is label that indicates
 * the data item containing the Y coordinate.
 *
 * This is used for both key types \ref T_COSE_KEY_TYPE_EC2 and \ref
 * T_COSE_KEY_TYPE_OKP.
 */
#define T_COSE_KEY_PARAM_PRIVATE_D  -4




/* ---------- COSE Key Types --------------------------------
 * https://www.iana.org/assignments/cose/cose.xhtml#key-type
 */

/**
 * \def T_COSE_KEY_TYPE_OKP
 *
 * \brief Key type is Octet Key Pair
 *
 * In a \c COSE_Key, this is a value of the data item labeled \ref
 * T_COSE_KEY_COMMON_KTY that indicates the \c COSE_Key is some sort of
 * key pair represented by some octets. It may or may not be an EC
 * key.
 */
#define T_COSE_KEY_TYPE_OKP       1

/**
 * \def T_COSE_KEY_TYPE_EC2
 *
 * \brief Key is a 2-parameter EC key.
 *
 * In a \c COSE_Key, this is a value of the data item labeled \ref
 * T_COSE_KEY_COMMON_KTY that indicates the \c COSE_Key is an EC key
 * specified with two coordinates, X and Y.
 */
#define T_COSE_KEY_TYPE_EC2       2

/**
 * \def T_COSE_KEY_TYPE_SYMMETRIC
 *
 * \brief Key is a symmetric key.
 *
 * In a \c COSE_Key, this is a value of the data item labeled \ref
 * T_COSE_KEY_COMMON_KTY that indicates the \c COSE_Key is a symmetric
 * key.
 */
#define T_COSE_KEY_TYPE_SYMMETRIC  4




/* ----------- COSE Elliptic Curves ---------------------
 * https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
 */

/**
 * \def T_COSE_ELLIPTIC_CURVE_P_256
 *
 * \brief Key type for NIST P-256 key
 *
 * In a \c COSE_Key, this is a value of the data item labeled \ref
 * T_COSE_KEY_PARAM_CRV to indicate the NIST P-256 curve, also known as
 * secp256r1.
 *
 * This key type is always \ref T_COSE_KEY_TYPE_EC2.
 */
#define T_COSE_ELLIPTIC_CURVE_P_256 1

/**
 * \def T_COSE_ELLIPTIC_CURVE_P_384
 *
 * \brief Key type for NIST P-384 key
 *
 * In a \c COSE_Key, this is a value of the data item labeled \ref
 * T_COSE_KEY_PARAM_CRV to indicate the NIST P-384 curve, also known as
 * secp384r1.
 *
 * This key type is always \ref T_COSE_KEY_TYPE_EC2.
 */
#define T_COSE_ELLIPTIC_CURVE_P_384 2

/**
 * \def T_COSE_ELLIPTIC_CURVE_P_521
 *
 * \brief Key type for NIST P-521 key
 *
 * In a \c COSE_Key, this is a value of the data item labeled \ref
 * T_COSE_KEY_PARAM_CRV to indicate the NIST P-521 curve, also known as
 * secp521r1.
 */
#define T_COSE_ELLIPTIC_CURVE_P_521 3

/**
 * \def T_COSE_ELLIPTIC_CURVE_X25519
 *
 * \brief X25519 key type for use with ECDH only
 */
#define T_COSE_ELLIPTIC_CURVE_X25519 4

/**
 * \def T_COSE_ELLIPTIC_CURVE_X448
 *
 * \brief X448 key type for use with ECDH only
 */
#define T_COSE_ELLIPTIC_CURVE_X448 5



/* ------- Constants from RFC 9180 ---------
 */

/**
 * HPKE KEM Identifiers
 */
#define T_COSE_HPKE_KEM_ID_P256             0x0010 ///< NIST P-256
#define T_COSE_HPKE_KEM_ID_P384             0x0011 ///< NIST P-256
#define T_COSE_HPKE_KEM_ID_P521             0x0012 ///< NIST P-521
#define T_COSE_HPKE_KEM_ID_25519            0x0020 ///< Curve25519
#define T_COSE_HPKE_KEM_ID_448              0x0021 ///< Curve448

/**
 * HPKE KDF Identifiers
 */
#define T_COSE_HPKE_KDF_ID_HKDF_SHA256      0x0001 ///< HKDF-SHA256
#define T_COSE_HPKE_KDF_ID_HKDF_SHA384      0x0002 ///< HKDF-SHA512
#define T_COSE_HPKE_KDF_ID_HKDF_SHA512      0x0003 ///< HKDF-SHA512

/**
 * HPKE AEAD Identifiers
 */
#define T_COSE_HPKE_AEAD_ID_AES_GCM_128     0x0001 ///< AES-GCM-128
#define T_COSE_HPKE_AEAD_ID_AES_GCM_256     0x0002 ///< AES-GCM-256
#define T_COSE_HPKE_AEAD_ID_CHACHA_POLY1305 0x0003 ///< Chacha20-Poly1305



/* ------- Constants from RFC 8152 ---------
 */

/**
 * \def COSE_SIG_CONTEXT_STRING_SIGNATURE1
 *
 * \brief This is a string constant used by COSE to label \c
 * COSE_Sign1 structures. See RFC 8152, section 4.4.
 */
#define COSE_SIG_CONTEXT_STRING_SIGNATURE1 "Signature1"

#define COSE_SIG_CONTEXT_STRING_SIGNATURE "Signature"


/**
 * \def COSE_MAC_CONTEXT_STRING_MAC0
 *
 * \brief This is a string constant used by COSE to label \c COSE_Mac0
 * structures. See RFC 8152, section 6.3.
 */
#define COSE_MAC_CONTEXT_STRING_MAC0 "MAC0"

#endif /* __T_COSE_STANDARD_CONSTANTS_H__ */
