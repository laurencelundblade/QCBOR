/*
 * init_keys.h
 *
 * Copyright 2023, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef init_keys_h
#define init_keys_h


#include "t_cose/t_cose_key.h"

/* Initializes a key to fixed test key for the specified algorithm
 *
 * This is used by examples and by test cases.
 *
 * Go read the source to learn how keys work for your
 * particular crypto library.
 *
 * This always initializes to the exact same key pair for
 * a given algorithm.  (This saves us having to pass in some
 * serialized representation of the key pair. It's (so far) not
 * straight forward for all the crypto libraries to support the
 * same serialization formats; for OSSL it's a DER format; for
 * Mbed TLS is a point on a curve).
 *
 * This interface is independent of the crypto library, but the
 * implementation is not.
 *
 * This is pulled out from the example to keep them independent
 * of any particular crypto library.
 *
 * free_fixed_signing_key() should be called when done with the
 * keys returned here to work for certain with all crypto libraries
 * even though some don't require it.
 *
 * TODO: should this be by curve instead of signing algorithm?
 *
 */
enum t_cose_err_t
init_fixed_test_signing_key(int32_t            cose_algorithm_id,
                            struct t_cose_key *key_pair);


void
free_fixed_signing_key(struct t_cose_key key_pair);




/* This is for key pairs for EC encryption (not symmetric
 * encryption). Typically this gets fed into ECDH either
 * for HPKE or the other COSE encryption key distrubution
 * methods.
 *
 * The curve and number of bits are associated with the key
 * not with the encryption algorithm, so this takes
 * the COSE EC curve ID as an argument, not the encryption
 * algorithm.
 *
 * While the crypto library representation of a private key
 * usually also includes the public key, they are split here
 * because that suits our test and example purposes much better.
 * In the real world, the encryptor will not have the private key.
 *
 * The actual keys can be the same as for ECDSA, but the
 * import can involve setting key usage bits so the import
 * function for keys used with ECDH is different than for
 * keys used with ECDSA.
 */
enum t_cose_err_t
init_fixed_test_ec_encryption_key(int32_t            cose_ec_curve_id,
                                  struct t_cose_key *public_key,
                                  struct t_cose_key *private_key);


void
free_fixed_test_ec_encryption_key(struct t_cose_key key);



/* Returns true if key pair leaks were detected. This is
 * necessary only for testing. Not all crypto libraries
 * support this.
 */
int check_for_key_allocation_leaks(void);

#endif /* init_keys_h */
