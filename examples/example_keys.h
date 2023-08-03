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
 * libraries is dependent on the library. The most widely used formats
 * are ASN.1/DER so that is mostly what is used here.  See
 * init_keys_xxx.[ch]. These are pretty good examples for what you
 * might do in your implementation.
 *
 * Eventually, t_cose will have better support for COSE_Key, but even
 * then most keys will still be in ASN.1/DER format.
 *
 * Note how ridiculously piece meal the formats for DER- encoded keys
 * are. Perhaps a dozen RFCs :-(. Implementations seem to be
 * hit-or-miss in what they support.  Maybe some day much more of this
 * will be CBOR-format COSE_Keys... :^)
 */




/*
 * The format of an EC key in a file or in a protocol message is in
 * 2-3 layers.
 *
 * First, SEC1 (reference below) byte-encoding of the mathematical values.
 *
 * Second, a structure that wraps the SEC1 bytes along with a curve
 * identifier. There are three:
 *    RFC 5480 and RFC 5915 — ASN.1/DER
 *    JWK — JSON 
 *    COSE_Key — CBOR
 *
 * Sometimes a third layer, PEM, to make ASN.1/DER into text.
 *
 * SEC1 defines the representation of the mathematical values use in EC
 * cryptography like an X and Y coordinate in bytes. The SEC1
 * specification is widely used as the basis of most protocol and file
 * formats and as for import and export formats for cryptographic
 * libraries.
 *
 * SEC1 defines private key serialization as a sequence of bytes.
 *
 * SEC1 defines the public key as a point, an X and Y coordinate. It
 * defines compressed and uncompressed formats. The compressed format
 * is half the size. It used to be covered by a patent, but the
 * patent has expired. The public key is serialized in one of three
 * ways:
 *    0x04 || X-coordinate || y-coordinate (uncompressed)
 *    0x02 || X-coordinate (compressed, Y positive)
 *    0x03 || X-coordinate (compressed, Y negative)
 *
 *
 * Generally, the SEC1 serialization is not used directly in
 * protocols. Rather it is put into an ASN.1/DER, JSON or CBOR data
 * structure. Often that additional structure identifies it as an EC
 * key and gives the curve.
 *
 * The most common protocol/file format for EC keys is ASN.1/DER
 * defined by RFC 5480 for public keys and RFC 5915 for private
 * keys. RFC 5915 can optionally carry a public key along side the
 * private key. These are the file formats that the “openssl ec”
 * command reads and writes.
 *
 * Here’s the ASN.1 from RFC 5915:
 *
 *   ECPrivateKey ::= SEQUENCE {
 *       version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *       privateKey     OCTET STRING,
 *       parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *       publicKey  [1] BIT STRING OPTIONAL
 *    }
 *
 * And the ASN.1 from RFC 5480:
 *
 *    SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *       algorithm         AlgorithmIdentifier,
 *       subjectPublicKey  BIT STRING
 *    }
 *
 *    AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm   OBJECT IDENTIFIER,
 *       parameters  ANY DEFINED BY algorithm OPTIONAL
 *    }
 *
 *    ECParameters ::= CHOICE {
 *       namedCurve         OBJECT IDENTIFIER
 *       -- implicitCurve   NULL
 *       -- specifiedCurve  SpecifiedECDomain
 *    }
 *
 * DER is a binary format, so it is often made into a PEM text file
 * for convenience of handling. PEM is more or less base64 encoding
 * with a little bit of extra text labeling to know the PEM file is a
 * key and whether it is public or private.
 *
 * -----BEGIN EC PRIVATE KEY-----
 * MHcCAQEEIK/5B8mfmtOq5sTN8hEivOK9aLUoPmkHFUrZEYQPogjPoAoGCCqGSM49
 * AwEHoUQDQgAEZe2loSV3wrroKUN/4zhwGhCqo3Xhu1td4QjeQ5wIVR0eUu11cBFj
 * 9/nkDd+fNBs9ybqGCvfgynyn6e7NAITRnA==
 * -----END EC PRIVATE KEY——
 *
 *
 * -----BEGIN PUBLIC KEY-----
 * MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZe2loSV3wrroKUN/4zhwGhCqo3Xh
 * u1td4QjeQ5wIVR0eUu11cBFj9/nkDd+fNBs9ybqGCvfgynyn6e7NAITRnA==
 * -----END PUBLIC KEY-----
 *
 * Not discussed here are X.509 certificates. It is comment to send
 * public keys around in them so you know where the public key came
 * from and can figure out how to trust it. X.509 is ASN.1/DER and
 * often PEM wrapped. The public key inside it is in RFC 5480 format.
 *
 * Each EC key supplied here is in several forms to accommodate
 * different cryptographic library import APIs, to give good examples
 * and for other use if need be. The SEC1 form is given and the
 * ASN.1/DER form is given. The PEM form is not given.
 *
 * Some of the keys are from the COSE examples GitHub repository and
 * some are not. The intent is to use as many from the COSE examples
 * as possible in the long run.
 *
 * [SEC1]
 * Certicom Research, "SEC 1: Elliptic Curve Cryptography", Standards for
 * Efficient Cryptography, May 2009, <https://www.secg.org/sec1-v2.pdf>.
 */

/*
 * This describes how I converted the keys in KeySet.txt to what is
 * here. The keys in KeySet.txt are CBOR diagnostic notation of a
 * COSE_Key.  They kinda look like JWKs, but they are not. I haven't
 * found any tools to process them yet.
 *
 * First I made the SEC1 bytes for private key and the public key:
 *
 *    xxd -r -p << EOD | xxd -i
 *
 * The hex text from KeySet.txt is fed into the above command stdin.
 * The hex text C array initialization output by this is pasted in to
 * example_keys.c. For the private key, just the "d" value. For the
 * public key the "x" and then "y" value. Then the C code is edited to
 * add a 0x04 to the start of the x and y.
 *
 * Next... (there has to be a better way), I generated a random key
 * pairs in DER format using the openssl command line for the curves:
 *
 *    openssl ecparam -name secp521r1 -genkey -noout -out 521.der -outform der
 *
 * That was imported into a C array initialization with:
 *
 *    xxd -i -c 8 521.der
 *
 * Then the C array initialization was edited to splice in the COSE
 * example private key and the the COSE example public key. You can
 * see the comments in the code for the ASN.1/DER to figure where to
 * splice.
 *
 * Finally the edited variables were turned into DER files and checked
 * in to github to have them handy for future use. See grep command in
 * // comment below that takes the C array initialization and turns it
 * into a binary DER file.
 */

//grep -v '/\*.*\*/' << EOF | xxd -r -p


extern const unsigned char ec_P_256_key_pair_der[121];
extern const unsigned char ec_P_256_priv_key_sec1[32];
extern const unsigned char ec_P_256_pub_key_der[91];


extern const unsigned char ec_P_384_key_pair_der[167];
extern const unsigned char ec_P_384_priv_key_sec1[48];

extern const unsigned char ec_P_521_key_pair_der[223];
extern const unsigned char ec_P_521_priv_key_sec1[66];



/* These keys are the ones used in the COSE Work Group GitHub
 * Examples Repository */
// KID: meriadoc.brandybuck@buckland.example
extern const unsigned char cose_ex_P_256_priv_sec1[32];
extern const unsigned char cose_ex_P_256_pub_sec1[65];
extern const unsigned char cose_ex_P_256_pair_der[121];
extern const unsigned char cose_ex_P_256_pub_der[91];

// KID: bilbo.baggins@hobbiton.example
extern const unsigned char cose_ex_P_521_priv_sec1[66];
extern const unsigned char cose_ex_P_521_pub_sec1[133];
extern const unsigned char cose_ex_P_521_pair_der[223];
extern const unsigned char cose_ex_P_521_pub_der[158];




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
