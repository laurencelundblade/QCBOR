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
 */
enum t_cose_err_t
init_fixed_test_signing_key(int32_t            cose_algorithm_id,
                            struct t_cose_key *key_pair);


void
free_fixed_signing_key(struct t_cose_key key_pair);




/* This is for key pairs for HPKE encryption (not symmetric
 * encryption). Lots still to figure out here especially
 * considering HPKE is still in flux.
 *
 * (It's fairly difficult (for me) to fully understand how key material
 * here works. There's a lot of variability (curves, serialization format,
 * generation algorithms). IMO, the APIs for these are not well documented,
 * nor are the tools. And then there's politics and opinionated
 * people...
 * Expect this to evolve...).
 *
 * The implementaiton of this can be crypto-library
 * dependent, but the actual example and test for HPKE can not.
 * It's only the key material inialization in t_cose that is
 * crypto-library dependent.
 *
 * Public key and private key are separate because it's not clear
 * if crypto libraries support a key pair here.
 *
 * These keys are used with ECDH. (With ECDSA it's possible
 * to have a key pair in one key handle with OpenSSL and Mbed TLS,
 * but not sure about ECDH) What about other libraries?
 */

enum t_cose_err_t
init_fixed_test_encryption_key(int32_t            cose_algorithm_id,
                               struct t_cose_key *public_key,
                               struct t_cose_key *private_key);


void
free_fixed_test_encryption_key(struct t_cose_key key_pair);



/* Returns true if key pair leaks were detected. This is
 * necessary only for testing. Not all crypto libraries
 * support this.
 */
int check_for_key_allocation_leaks(void);

#endif /* init_keys_h */
