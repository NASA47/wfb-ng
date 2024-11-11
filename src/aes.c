#include "aes.h"

int sw_crypto_aead_aes256gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                                        unsigned char *aad, int aad_len,
                                        unsigned char *key,
                                        unsigned char *iv, int iv_len,
                                        unsigned char *ciphertext, long long unsigned int *ciphertext_len)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    const int tag_len = 16;
    unsigned char tag[tag_len];

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    *ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    *ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag))
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    memcpy(ciphertext + *ciphertext_len, tag, tag_len);
    *ciphertext_len += tag_len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}


int sw_crypto_aead_aes256gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                                        const unsigned char *aad, int aad_len,                
                                        unsigned char *key,
                                        unsigned char *iv, int iv_len,
                                        unsigned char *plaintext, unsigned long long *plaintext_len)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ret;

    const int tag_len = 16;   
    ciphertext_len -= tag_len;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    *plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, ciphertext + ciphertext_len))
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret <= 0) {
        /* Verify failed */
        return -1;
    }
    
    *plaintext_len += len;

    return 0;
}