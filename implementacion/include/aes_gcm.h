#ifndef AES_GCM_H
#define AES_GCM_H

#include <stdint.h>
#include <stddef.h>

/* AES-128-GCM Parameters */
#define AES_KEY_SIZE        16  // 128 bits
#define AES_NONCE_SIZE      12  // 96 bits (recommended for GCM)
#define AES_TAG_SIZE        16  // 128 bits
#define AES_BLOCK_SIZE      16  // 128 bits

#define AES_GCM_SUCCESS     0
#define AES_GCM_ERR_AUTH   -1
#define AES_GCM_ERR_INIT   -2

typedef uint8_t byte_t;

/**
 * AES-128-GCM encryption using OpenSSL
 *
 * @param key        16-byte key
 * @param nonce      12-byte nonce (96 bits recommended for GCM)
 * @param ad         Associated data (can be NULL if ad_len == 0)
 * @param ad_len     Length of associated data
 * @param plaintext  Plaintext message
 * @param pt_len     Length of plaintext
 * @param ciphertext Output ciphertext buffer (same size as plaintext)
 * @param tag        Output 16-byte authentication tag
 * @return AES_GCM_SUCCESS on success, error code otherwise
 */
int aes_gcm_encrypt(
    const byte_t *key,
    const byte_t *nonce,
    const byte_t *ad, size_t ad_len,
    const byte_t *plaintext, size_t pt_len,
    byte_t *ciphertext,
    byte_t *tag
);

/**
 * AES-128-GCM decryption and verification using OpenSSL
 *
 * @param key        16-byte key
 * @param nonce      12-byte nonce (96 bits)
 * @param ad         Associated data (can be NULL if ad_len == 0)
 * @param ad_len     Length of associated data
 * @param ciphertext Ciphertext message
 * @param ct_len     Length of ciphertext
 * @param tag        16-byte authentication tag to verify
 * @param plaintext  Output plaintext buffer (same size as ciphertext)
 * @return AES_GCM_SUCCESS on success, AES_GCM_ERR_AUTH if tag verification fails
 */
int aes_gcm_decrypt(
    const byte_t *key,
    const byte_t *nonce,
    const byte_t *ad, size_t ad_len,
    const byte_t *ciphertext, size_t ct_len,
    const byte_t *tag,
    byte_t *plaintext
);

#endif /* AES_GCM_H */
