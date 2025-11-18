#ifndef GIFT_COFB_H
#define GIFT_COFB_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* GIFT-128 Parameters */
#define GIFT_BLOCK_SIZE     16  // 128 bits
#define GIFT_KEY_SIZE       16  // 128 bits
#define GIFT_NONCE_SIZE     8   // 64 bits (same as GFRX for fair comparison)
#define GIFT_TAG_SIZE       16  // 128 bits
#define GIFT_ROUNDS         40
#define GIFT_HALF_BLOCK     8

#define GIFT_SUCCESS        0
#define GIFT_ERR_INVALID   -1
#define GIFT_ERR_AUTH      -2

typedef uint8_t byte_t;
typedef uint32_t word32_t;

/* GIFT-128 context */
typedef struct {
    word32_t round_keys[2 * GIFT_ROUNDS];  // Round keys
    word32_t state[4];                     // 128-bit state (4x32 bits)
} gift_ctx_t;

/* GIFT-COFB context */
typedef struct {
    gift_ctx_t gift;
    uint64_t delta;
    byte_t Y[GIFT_BLOCK_SIZE];
    size_t ad_blocks;
    size_t msg_blocks;
} gift_cofb_ctx_t;

/**
 * Initialize GIFT-128 context with key
 */
int gift_init(gift_ctx_t *ctx, const byte_t *key);

/**
 * Encrypt one block with GIFT-128
 */
void gift_encrypt_block(const gift_ctx_t *ctx, const byte_t *plaintext, byte_t *ciphertext);

/**
 * Decrypt one block with GIFT-128
 */
void gift_decrypt_block(const gift_ctx_t *ctx, const byte_t *ciphertext, byte_t *plaintext);

/**
 * GIFT-COFB encryption
 */
int gift_cofb_encrypt(
    const byte_t *key,
    const byte_t *nonce,
    const byte_t *ad, size_t ad_len,
    const byte_t *plaintext, size_t plaintext_len,
    byte_t *ciphertext,
    byte_t *tag
);

/**
 * GIFT-COFB decryption and verification
 */
int gift_cofb_decrypt(
    const byte_t *key,
    const byte_t *nonce,
    const byte_t *ad, size_t ad_len,
    const byte_t *ciphertext, size_t ciphertext_len,
    const byte_t *tag,
    byte_t *plaintext
);

#endif /* GIFT_COFB_H */
