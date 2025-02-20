#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

enum
{
    AES_SUCCESS = 0,
    AES_FAIL = -1,
};

int openssl_crypto_aead_aes256gcm_encrypt(unsigned char *ciphertext, long long unsigned int *ciphertext_len,
                                          unsigned char *plaintext, int plaintext_len,
                                          unsigned char *aad, int aad_len,
                                          const unsigned char *nsec,
                                          unsigned char *iv,
                                          unsigned char *key);
int openssl_crypto_aead_aes256gcm_decrypt(unsigned char *plaintext, unsigned long long *plaintext_len,
                                          unsigned char *nsec,
                                          const unsigned char *ciphertext, unsigned long long ciphertext_len,
                                          const unsigned char *aad, unsigned long long aad_len,
                                          unsigned char *iv,
                                          unsigned char *key);