#include "none.h"

int none_encrypt(unsigned char *ciphertext, long long unsigned int *ciphertext_len,
                                        unsigned char *plaintext, int plaintext_len,
                                        unsigned char *aad, int aad_len,
                                        const unsigned char *nsec,
                                        unsigned char *iv,
                                        unsigned char *key)
{
    *ciphertext_len = plaintext_len;
    memcpy(ciphertext, plaintext, plaintext_len);

    return NONE_SUCCESS;
}


int none_decrypt(unsigned char *plaintext, unsigned long long *plaintext_len,
                                        unsigned char *nsec,
                                        const unsigned char *ciphertext, unsigned long long ciphertext_len,
                                        const unsigned char *aad, unsigned long long aad_len,
                                        unsigned char *iv,
                                        unsigned char *key)
{
    *plaintext_len = ciphertext_len;
    memcpy(plaintext, ciphertext, ciphertext_len);

    return NONE_SUCCESS;
}