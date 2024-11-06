#include "aes.h"

static const int OPENSSL_SUCCESS = 1;

/* Current implementation of WFB-NG uses hardcoded 12 bytes (96 bits) IV length
 * and hardcoded 16 bytes (128 bits) TAG length.
 */
static const int IV_LEN = 12;
static const int TAG_LEN = 16;

static void handle_errors(EVP_CIPHER_CTX *ctx)
{
    ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);
}

int sw_crypto_aead_aes256gcm_encrypt(unsigned char *ciphertext, long long unsigned int *ciphertext_len,
                                        unsigned char *plaintext, int plaintext_len,
                                        unsigned char *aad, int aad_len,
                                        const unsigned char *nsec,
                                        unsigned char *iv,
                                        unsigned char *key)
{
    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
    {
        handle_errors(ctx);
        return AES_FAIL;
    }

    /* Initialise the encryption operation. */
    if(OPENSSL_SUCCESS != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    {
        handle_errors(ctx);
        return AES_FAIL;
    }

    /* Set IV length */
    if(OPENSSL_SUCCESS != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL))
    {
        handle_errors(ctx);
        return AES_FAIL;
    }

    /* Initialise key and IV */
    if(OPENSSL_SUCCESS != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
    {
        handle_errors(ctx);
        return AES_FAIL;
    }

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    int len = 0;
    if(OPENSSL_SUCCESS != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
    {
        handle_errors(ctx);
        return AES_FAIL;
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(OPENSSL_SUCCESS != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        handle_errors(ctx);
        return AES_FAIL;
    }
    *ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(OPENSSL_SUCCESS != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        handle_errors(ctx);
        return AES_FAIL;
    }
    *ciphertext_len += len;

    /* Get the tag */
    unsigned char tag[TAG_LEN];
    if(OPENSSL_SUCCESS != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag))
    {
        handle_errors(ctx);
        return AES_FAIL;
    }

    memcpy(ciphertext + *ciphertext_len, tag, TAG_LEN);
    *ciphertext_len += TAG_LEN;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return AES_SUCCESS;
}


int sw_crypto_aead_aes256gcm_decrypt(unsigned char *plaintext, unsigned long long *plaintext_len,
                                        unsigned char *nsec,
                                        const unsigned char *ciphertext, unsigned long long ciphertext_len,
                                        const unsigned char *aad, unsigned long long aad_len,
                                        unsigned char *iv,
                                        unsigned char *key)
{
    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
    {
        handle_errors(ctx);
        return AES_FAIL;
    }

    /* Initialise the decryption operation. */
    if(OPENSSL_SUCCESS != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    {
        handle_errors(ctx);
        return AES_FAIL;
    }

    /* Set IV length. */
    if(OPENSSL_SUCCESS != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL))
    {
        handle_errors(ctx);
        return AES_FAIL;
    }

    /* Initialise key and IV */
    if(OPENSSL_SUCCESS != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    {
        handle_errors(ctx);
        return AES_FAIL;
    }

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    int len = 0;
    if(OPENSSL_SUCCESS != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
    {
        handle_errors(ctx);
        return AES_FAIL;
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    ciphertext_len -= TAG_LEN;
    if(OPENSSL_SUCCESS != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        handle_errors(ctx);
        return AES_FAIL;
    }
    *plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(OPENSSL_SUCCESS != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)(ciphertext + ciphertext_len)))
    {
        handle_errors(ctx);
        return AES_FAIL;
    }

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    if(0 >= EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        /* Verify failed */
        handle_errors(ctx);
        return AES_FAIL;
    }

    *plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return AES_SUCCESS;
}