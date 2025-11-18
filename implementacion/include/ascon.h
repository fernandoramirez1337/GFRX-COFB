#ifndef ASCON_H
#define ASCON_H

#include <stdint.h>
#include <stddef.h>

/* ASCON-128 Parameters */
#define ASCON_RATE          8   // 64 bits
#define ASCON_KEY_SIZE      16  // 128 bits
#define ASCON_NONCE_SIZE    16  // 128 bits
#define ASCON_TAG_SIZE      16  // 128 bits
#define ASCON_STATE_SIZE    40  // 320 bits (5x64 bits)

#define ASCON_SUCCESS       0
#define ASCON_ERR_AUTH     -1

typedef uint8_t byte_t;
typedef uint64_t word64_t;

/* ASCON state: 5 words of 64 bits each */
typedef struct {
    word64_t x[5];
} ascon_state_t;

/* ASCON AEAD context */
typedef struct {
    ascon_state_t state;
    byte_t key[ASCON_KEY_SIZE];
} ascon_ctx_t;

/**
 * ASCON-128 encryption
 *
 * @param key        16-byte key
 * @param nonce      16-byte nonce
 * @param ad         Associated data (can be NULL if ad_len == 0)
 * @param ad_len     Length of associated data
 * @param plaintext  Plaintext message
 * @param pt_len     Length of plaintext
 * @param ciphertext Output ciphertext buffer (same size as plaintext)
 * @param tag        Output 16-byte authentication tag
 * @return ASCON_SUCCESS on success
 */
int ascon_encrypt(
    const byte_t *key,
    const byte_t *nonce,
    const byte_t *ad, size_t ad_len,
    const byte_t *plaintext, size_t pt_len,
    byte_t *ciphertext,
    byte_t *tag
);

/**
 * ASCON-128 decryption and verification
 *
 * @param key        16-byte key
 * @param nonce      16-byte nonce
 * @param ad         Associated data (can be NULL if ad_len == 0)
 * @param ad_len     Length of associated data
 * @param ciphertext Ciphertext message
 * @param ct_len     Length of ciphertext
 * @param tag        16-byte authentication tag to verify
 * @param plaintext  Output plaintext buffer (same size as ciphertext)
 * @return ASCON_SUCCESS on success, ASCON_ERR_AUTH if tag verification fails
 */
int ascon_decrypt(
    const byte_t *key,
    const byte_t *nonce,
    const byte_t *ad, size_t ad_len,
    const byte_t *ciphertext, size_t ct_len,
    const byte_t *tag,
    byte_t *plaintext
);

#endif /* ASCON_H */
