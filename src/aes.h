#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

void handleErrors(void);
int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                long long unsigned int *ciphertext_len);
int gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *aad, int aad_len,                
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext);