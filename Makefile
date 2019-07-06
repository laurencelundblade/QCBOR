OSSL_INC=-I ../../openssl/openssl-1.1.1b/include/openssl -I ../../openssl/openssl-1.1.1b/include
PSA_INC=-I ../../TF-M/trusted-firmware-m/interface/include -I ../../TF-M/trusted-firmware-m/secure_fw/services/initial_attestation
PSA_CRYPTO_INC=
HASH_INC=-I ../../crypto-algorithms
QCBOR_INC= -I ../../QCBOR/master/inc
INC=-I inc -I Test  -I src
ALL_INC=$(OSSL_INC) $(PSA_INC) $(QCBOR_INC) $(INC) $(HASH_INC)

C_OPTS=-Os -Wall -pedantic-errors -Wextra -Wshadow -Wparentheses -xc -std=c99

CFLAGS=$(ALL_INC) $(C_OPTS)

SRC_OBJ=src/t_cose_sign1_verify.o src/t_cose_sign1_sign.o src/t_cose_util.o 

TEST_OBJ=test/t_cose_test.o

PSA_CRYPTO_OBJ=crypto_adapters/t_cose_psa_off_target_hashes.o crypto_adapters/t_cose_psa_off_target_signature.o ../../crypto-algorithms/sha256.o crypto_adapters/t_cose_psa_crypto_hash.o crypto_adapters/t_cose_openssl_signature.o

OSSL_CRYPTO_OBJ=crypto_adapters/t_cose_openssl_signature.o crypto_adapters/t_cose_b_con_hash.o ../../crypto-algorithms/sha256.o

QCBOR=../../QCBOR/master/libqcbor.a
LIBCRYPT=../../openssl/openssl-1.1.1b/libcrypto.a

t_cose_test: main.o $(SRC_OBJ) $(OSSL_CRYPTO_OBJ) $(TEST_OBJ)
	cc -o $@ $^ $(QCBOR) $(LIBCRYPT)


clean:
	rm -f $(SRC_OBJ) $(TEST_OBJ) $(OSSL_CRYPTO_OBJ) $(TEST_OBJ2) $(PSA_CRYPTO_OBJ)
