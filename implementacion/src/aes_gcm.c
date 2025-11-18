/**
 * AES-128-GCM AEAD Implementation using OpenSSL
 */

#include "aes_gcm.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* AES-128-GCM encryption */
int aes_gcm_encrypt(
    const byte_t *key,
    const byte_t *nonce,
    const byte_t *ad, size_t ad_len,
    const byte_t *plaintext, size_t pt_len,
    byte_t *ciphertext,
    byte_t *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    /* Create and initialize the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return AES_GCM_ERR_INIT;
    }

    /* Initialize encryption operation with AES-128-GCM */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_GCM_ERR_INIT;
    }

    /* Set nonce length (96 bits = 12 bytes) */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_NONCE_SIZE, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_GCM_ERR_INIT;
    }

    /* Initialize key and nonce */
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_GCM_ERR_INIT;
    }

    /* Provide associated data (AAD) */
    if (ad_len > 0 && ad != NULL) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, ad, ad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return AES_GCM_ERR_INIT;
        }
    }

    /* Encrypt plaintext */
    if (pt_len > 0) {
        if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, pt_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return AES_GCM_ERR_INIT;
        }
        ciphertext_len = len;

        /* Finalize encryption */
        if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return AES_GCM_ERR_INIT;
        }
        ciphertext_len += len;
    }

    /* Get the tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_GCM_ERR_INIT;
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return AES_GCM_SUCCESS;
}

/* AES-128-GCM decryption */
int aes_gcm_decrypt(
    const byte_t *key,
    const byte_t *nonce,
    const byte_t *ad, size_t ad_len,
    const byte_t *ciphertext, size_t ct_len,
    const byte_t *tag,
    byte_t *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialize the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return AES_GCM_ERR_INIT;
    }

    /* Initialize decryption operation with AES-128-GCM */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_GCM_ERR_INIT;
    }

    /* Set nonce length */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_NONCE_SIZE, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_GCM_ERR_INIT;
    }

    /* Initialize key and nonce */
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_GCM_ERR_INIT;
    }

    /* Provide associated data (AAD) */
    if (ad_len > 0 && ad != NULL) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, ad, ad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return AES_GCM_ERR_INIT;
        }
    }

    /* Decrypt ciphertext */
    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ct_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return AES_GCM_ERR_INIT;
        }
        plaintext_len = len;
    } else {
        plaintext_len = 0;
    }

    /* Set expected tag value */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE, (void *)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_GCM_ERR_INIT;
    }

    /* Finalize decryption and verify tag */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        /* Success - tag verified */
        plaintext_len += len;
        return AES_GCM_SUCCESS;
    } else {
        /* Tag verification failed */
        memset(plaintext, 0, ct_len);
        return AES_GCM_ERR_AUTH;
    }
}
