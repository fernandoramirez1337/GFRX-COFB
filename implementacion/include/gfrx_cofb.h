#ifndef GFRX_COFB_H
#define GFRX_COFB_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define GFRX_BLOCK_SIZE     16
#define GFRX_KEY_SIZE       16
#define GFRX_NONCE_SIZE     8
#define GFRX_TAG_SIZE       16
#define GFRX_ROUNDS         32
#define COFB_HALF_BLOCK     8

#define GFRX_SUCCESS        0
#define GFRX_ERR_INVALID   -1
#define GFRX_ERR_AUTH     -2
#define GFRX_ERR_MEMORY    -3

typedef uint8_t byte_t;
typedef uint32_t word32_t;

typedef struct {
    word32_t round_keys[4 * GFRX_ROUNDS];
    word32_t state[4];
} gfrx_ctx_t;

typedef struct {
    gfrx_ctx_t gfrx;
    uint64_t delta;
    byte_t Y[GFRX_BLOCK_SIZE];
    size_t ad_blocks;
    size_t msg_blocks;
} cofb_ctx_t;

int gfrx_init(gfrx_ctx_t *ctx, const byte_t *key);
void gfrx_encrypt_block(const gfrx_ctx_t *ctx, const byte_t *plaintext, byte_t *ciphertext);
void gfrx_decrypt_block(const gfrx_ctx_t *ctx, const byte_t *ciphertext, byte_t *plaintext);

int cofb_init(cofb_ctx_t *ctx, const byte_t *key, const byte_t *nonce);
int cofb_encrypt(const byte_t *key, const byte_t *nonce, const byte_t *ad, size_t ad_len,
                 const byte_t *plaintext, size_t plaintext_len, byte_t *ciphertext, byte_t *tag);
int cofb_decrypt(const byte_t *key, const byte_t *nonce, const byte_t *ad, size_t ad_len,
                 const byte_t *ciphertext, size_t ciphertext_len, const byte_t *tag, byte_t *plaintext);

int secure_compare(const byte_t *a, const byte_t *b, size_t len);
void secure_zero(void *ptr, size_t len);

#endif // GFRX_COFB_H
