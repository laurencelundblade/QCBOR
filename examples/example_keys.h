/*
 * example_keys.h
 *
 * Copyright 2023, Laurence Lundblade
 *
 * Created by Laurence Lundblade on 6/13/23.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef example_keys_h
#define example_keys_h


/* These are hard-coded keys used for testing. A big reason for hard
 * coding in byte arrays is so that tests don't need any extra
 * files. Everything for test compiles into one executable.
 *
 * The actual import of the keys into data structures used by crypto
 * libraries is highly dependent on the library.  In many cases, but
 * not all, the key bytes are not dependent on the library because
 * there are standards for for serialized keys. The method to import
 * the keys is however highly dependent on the library as well as the
 * data structure that holds the keys. t_cose abstract the data
 * structure as a struct t_cose_key.  The varying import functions are
 * in init_keys_xxxx.[ch].
 *
 * Note how ridiculously piece meal the formats for DER-
 * encoded keys are. Perhaps a dozen RFCs :-(. Implementations
 * seem to be hit-or-miss in what they support.
 *
 * Also, this doesn't get into any password protected key formats.
 *
 * Some day this will all be CBOR-format COSE_Keys... :^)
 */




/*
 * Each EC NIST curve key is in two formats here, RFC 5915 DER format and a
 * raw private key format. This is needed because OpenSSL primarily supports
 * the DER formats and MbedTLS the raw private key.  The underly bit
 * serialization of the key is SEC1 for both.  Three key sizes are
 * provided.
 *
 * Importing in both cases yields a key pair (public and private).
 * MbedTLS will compute the public key from the private. The DER
 * format imported for OpenSSL includes the public key.
 *
 * The MbedTLS import function psa_import_key() is reasonably well
 * document and seems to support only the raw format.
 *
 * There are several ways to import in OpenSSL and the documentation
 * is not clear. d2i_PrivateKey() is what is used because it seems
 * supported in the range of OpenSSL versions and is not deprecated.
 *
 * It is my understanding (so far) that these key pairs can be used
 * with ECDSA for signing and ECDH for encryption.
 *
 * At 256 bits this is the NIST P-256 curve, AKA prime256v1 or
 * secp256r1.
 *
 * The DER format includes a curve identifier. The raw format does not
 * so it has to be specified during the key import.
 *
 *  ECPrivateKey ::= SEQUENCE {
 *     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *     privateKey     OCTET STRING,
 *     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *     publicKey  [1] BIT STRING OPTIONAL
 *  }
 *
 * Here's a dump of the DER for the 256-bit key. If you look, you'll
 * see that the private key in the DER is exactly the same values as
 * the raw private key string here.
 *
 *   0:d=0  hl=2 l= 119 cons: SEQUENCE
 *   2:d=1  hl=2 l=   1 prim: INTEGER           :01
 *   5:d=1  hl=2 l=  32 prim: OCTET STRING      [HEX DUMP]:D9B5E71F7728BFE563A9DC937562277E327D98D99480F3DC9241E5742AC45889
 *  39:d=1  hl=2 l=  10 cons: cont [ 0 ]
 *  41:d=2  hl=2 l=   8 prim: OBJECT            :prime256v1
 *  51:d=1  hl=2 l=  68 cons: cont [ 1 ]
 *  53:d=2  hl=2 l=  66 prim: BIT STRING
 *
 * Here's another dump from another tool of the same key.
 *
 * 30 77
 *  02 01 01    integer version 01
 *  04 20 D9B5E71F7728BFE563A9DC937562277E327D98D99480F3DC9241E5742AC45889   Private key
 *  A0 0A
 *    06 08 2A8648CE3D030107    OID for prime256v1
 *  A1 44
 *    03 42 000440416C8CDAA0F7A175695553C3279C109CE9277E53C5862AA715EDC636F171... Public key bit string
 *
 * X 40 41 6C 8C DA A0 F7 A1 75 69 55 53 C3 27 9C 10 9C E9 27 7E 53 C5 86 2A A7 15 ED C6 36 F1 71 
 * Y 32 F1 76 43 54 96 15 E5 C8 34 0D 43 32 DD 13 77 8A EC 87 15 76 A3 3C 26 08 6C 32 0C 9F F3 3F C7
 * See also:
 *  https://stackoverflow.com/questions/71890050/set-an-evp-pkey-from-ec-raw-points-pem-or-der-in-both-openssl-1-1-1-and-3-0-x/71896633#71896633
 *
 * [SEC1]
 * Certicom Research, "SEC 1: Elliptic Curve Cryptography", Standards for
 * Efficient Cryptography, May 2009, <https://www.secg.org/sec1-v2.pdf>.
 *
 * Note that there are also standard public key only formats. They aren't used
 * here because the test uses always need a private key, but some
 * applications and uses of t_cose might use them.
 */
extern const unsigned char ec_P_256_key_pair_der[121];
extern const unsigned char ec_P_256_priv_key_raw[32];
extern const unsigned char ec_P_256_pub_key_der[91];


extern const unsigned char ec_P_384_key_pair_der[167];
extern const unsigned char ec_P_384_priv_key_raw[48];

extern const unsigned char ec_P_521_key_pair_der[223];
extern const unsigned char ec_P_521_priv_key_raw[66];



/* These keys are the ones used in the COSE Work Group GitHub Examples Repository */
extern const unsigned char cose_ex_P_256_priv_key_raw[32];
extern const unsigned char cose_ex_P_256_key_pair_der[121];



/*
 * The RSA keypair is provided only in PKCS #1 DER format
 * as both OpenSSL and MbedTLS can import it. PKCS #1 is
 * documented in RFC 8017.
 *
 * This is imported with psa_import_key() in Mbed TLS
 * and d2i_PrivateKey().
 *
 * RSAPrivateKey ::= SEQUENCE {
 *    version   Version,
 *    modulus   INTEGER,  -- n
 *    publicExponentINTEGER,  -- e
 *    privateExponent   INTEGER,  -- d
 *    prime1INTEGER,  -- p
 *    prime2INTEGER,  -- q
 *    exponent1 INTEGER,  -- d mod (p-1)
 *    exponent2 INTEGER,  -- d mod (q-1)
 *    coefficient   INTEGER,  -- (inverse of q) mod p
 *    otherPrimeInfos   OtherPrimeInfos OPTIONAL
 * }
 *
 * PKCS 8 is another format for a private key, but
 * that is not provided.
 *
 * This was generated with:
 *   openssl genrsa 2048 | sed -e '1d' -e '$d' | base64 --decode  | xxd -i
 *
 */
extern const unsigned char RSA_2048_key_pair_der[1191];




/* Pretty sure this is per RFC 8410 in DER (which is
 * based on RFC 5958). This is imported by
 * d2i_PrivateKey() in OpenSSL. MbedTLS doesn't
 * support EdDSA.
 *
 *  OneAsymmetricKey ::= SEQUENCE {
 *     version Version,
 *     privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
 *     privateKey PrivateKey,
 *     attributes [0] IMPLICIT Attributes OPTIONAL,
 *     ...,
 *     [[2: publicKey [1] IMPLICIT PublicKey OPTIONAL ]],
 *     ...
 *  }
 *
 *  PrivateKey ::= OCTET STRING
 *
 *  PublicKey ::= BIT STRING
 *
 *  0:d=0  hl=2 l=  46 cons: SEQUENCE
 *  2:d=1  hl=2 l=   1 prim: INTEGER           :00
 *  5:d=1  hl=2 l=   5 cons: SEQUENCE
 *  7:d=2  hl=2 l=   3 prim: OBJECT            :ED25519
 * 12:d=1  hl=2 l=  34 prim: OCTET STRING      [HEX DUMP]:04205FE39B7455A073D138C2E7D4E50630529FCE7DDCE822802A685DA899165D4458
 */
extern const unsigned char ed25519_key_pair_der[48];


#endif /* example_keys_h */
