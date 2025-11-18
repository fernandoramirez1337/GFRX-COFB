/**
 * GIFT-COFB AEAD Implementation
 * COFB mode with GIFT-128 as underlying block cipher
 */

#include "gift_cofb.h"
#include <stdio.h>
#include <stdlib.h>

#define POLY64 0x1B

/* Compute mask for COFB mode */
static uint64_t compute_mask(uint64_t delta, int a, int b) {
    uint64_t mask = delta;
    for (int i = 0; i < a; i++) {
        uint64_t msb = mask >> 63;
        mask <<= 1;
        if (msb) {
            mask ^= POLY64;
        }
    }
    if (b == 1) {
        uint64_t temp = mask;
        uint64_t msb = mask >> 63;
        mask <<= 1;
        if (msb) {
            mask ^= POLY64;
        }
        mask ^= temp;
    }
    return mask;
}

/* G function for COFB */
static void G_function(const byte_t *Y, byte_t *result) {
    uint32_t Y1 = ((uint32_t)Y[0]) | ((uint32_t)Y[1] << 8) |
                  ((uint32_t)Y[2] << 16) | ((uint32_t)Y[3] << 24);
    uint32_t Y2 = ((uint32_t)Y[4]) | ((uint32_t)Y[5] << 8) |
                  ((uint32_t)Y[6] << 16) | ((uint32_t)Y[7] << 24);
    uint32_t Y3 = ((uint32_t)Y[8]) | ((uint32_t)Y[9] << 8) |
                  ((uint32_t)Y[10] << 16) | ((uint32_t)Y[11] << 24);
    uint32_t Y4 = ((uint32_t)Y[12]) | ((uint32_t)Y[13] << 8) |
                  ((uint32_t)Y[14] << 16) | ((uint32_t)Y[15] << 24);

    uint32_t G1 = Y2;
    uint32_t G2 = Y3;
    uint32_t G3 = Y4;
    uint32_t G4 = Y4 ^ Y1;

    result[0] = G1 & 0xFF; result[1] = (G1 >> 8) & 0xFF;
    result[2] = (G1 >> 16) & 0xFF; result[3] = (G1 >> 24) & 0xFF;
    result[4] = G2 & 0xFF; result[5] = (G2 >> 8) & 0xFF;
    result[6] = (G2 >> 16) & 0xFF; result[7] = (G2 >> 24) & 0xFF;
    result[8] = G3 & 0xFF; result[9] = (G3 >> 8) & 0xFF;
    result[10] = (G3 >> 16) & 0xFF; result[11] = (G3 >> 24) & 0xFF;
    result[12] = G4 & 0xFF; result[13] = (G4 >> 8) & 0xFF;
    result[14] = (G4 >> 16) & 0xFF; result[15] = (G4 >> 24) & 0xFF;
}

/* Rho function for encryption */
static void rho_function(const byte_t *Y, const byte_t *M, byte_t *X, byte_t *C, size_t len) {
    byte_t G_Y[GIFT_BLOCK_SIZE];
    G_function(Y, G_Y);

    for (size_t i = 0; i < len; i++) {
        X[i] = G_Y[i] ^ M[i];
    }
    for (size_t i = len; i < GIFT_BLOCK_SIZE; i++) {
        X[i] = G_Y[i];
    }

    if (C != NULL) {
        for (size_t i = 0; i < len; i++) {
            C[i] = Y[i] ^ M[i];
        }
    }
}

/* Rho inverse for decryption */
static void rho_inverse(const byte_t *Y, const byte_t *C, byte_t *X, byte_t *M, size_t len) {
    byte_t G_Y[GIFT_BLOCK_SIZE];
    byte_t M_padded[GIFT_BLOCK_SIZE];
    G_function(Y, G_Y);

    memset(M_padded, 0, GIFT_BLOCK_SIZE);
    for (size_t i = 0; i < len; i++) {
        M_padded[i] = Y[i] ^ C[i];
        if (M != NULL) {
            M[i] = M_padded[i];
        }
    }

    for (size_t i = 0; i < GIFT_BLOCK_SIZE; i++) {
        X[i] = G_Y[i] ^ M_padded[i];
    }
}

/* Initialize GIFT-COFB context */
static int gift_cofb_init(gift_cofb_ctx_t *ctx, const byte_t *key, const byte_t *nonce) {
    if (!ctx || !key || !nonce) {
        return GIFT_ERR_INVALID;
    }

    gift_init(&ctx->gift, key);

    byte_t nonce_block[GIFT_BLOCK_SIZE];
    memset(nonce_block, 0, GIFT_BLOCK_SIZE);
    memcpy(nonce_block, nonce, GIFT_NONCE_SIZE);

    gift_encrypt_block(&ctx->gift, nonce_block, ctx->Y);

    /* Initialize delta (first 64 bits of Y) */
    ctx->delta = 0;
    for (int i = 0; i < 8; i++) {
        ctx->delta |= ((uint64_t)ctx->Y[i]) << (8 * i);
    }

    ctx->ad_blocks = 0;
    ctx->msg_blocks = 0;

    return GIFT_SUCCESS;
}

/* XOR mask into block */
static void xor_mask(byte_t *block, uint64_t mask) {
    for (int i = 0; i < 8; i++) {
        block[i] ^= (mask >> (8 * i)) & 0xFF;
    }
}

/* Secure comparison */
static int secure_compare(const byte_t *a, const byte_t *b, size_t len) {
    int diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff;
}

/* GIFT-COFB encryption */
int gift_cofb_encrypt(
    const byte_t *key,
    const byte_t *nonce,
    const byte_t *ad, size_t ad_len,
    const byte_t *plaintext, size_t plaintext_len,
    byte_t *ciphertext,
    byte_t *tag)
{
    gift_cofb_ctx_t ctx;

    if (gift_cofb_init(&ctx, key, nonce) != GIFT_SUCCESS) {
        return GIFT_ERR_INVALID;
    }

    /* Process associated data */
    size_t ad_blocks = (ad_len + GIFT_BLOCK_SIZE - 1) / GIFT_BLOCK_SIZE;
    for (size_t i = 0; i < ad_blocks; i++) {
        size_t block_len = (i == ad_blocks - 1 && ad_len % GIFT_BLOCK_SIZE != 0)
                          ? ad_len % GIFT_BLOCK_SIZE
                          : GIFT_BLOCK_SIZE;

        byte_t ad_block[GIFT_BLOCK_SIZE];
        memset(ad_block, 0, GIFT_BLOCK_SIZE);
        memcpy(ad_block, ad + i * GIFT_BLOCK_SIZE, block_len);

        if (block_len < GIFT_BLOCK_SIZE) {
            ad_block[block_len] = 0x80;
        }

        byte_t X[GIFT_BLOCK_SIZE];
        rho_function(ctx.Y, ad_block, X, NULL, block_len);

        uint64_t mask = compute_mask(ctx.delta, i, (block_len < GIFT_BLOCK_SIZE) ? 1 : 0);
        xor_mask(X, mask);

        gift_encrypt_block(&ctx.gift, X, ctx.Y);
    }

    /* Process plaintext */
    size_t msg_blocks = (plaintext_len + GIFT_BLOCK_SIZE - 1) / GIFT_BLOCK_SIZE;
    if (plaintext_len == 0) msg_blocks = 0;

    for (size_t i = 0; i < msg_blocks; i++) {
        size_t block_len = (i == msg_blocks - 1 && plaintext_len % GIFT_BLOCK_SIZE != 0)
                          ? plaintext_len % GIFT_BLOCK_SIZE
                          : GIFT_BLOCK_SIZE;

        byte_t M[GIFT_BLOCK_SIZE];
        memset(M, 0, GIFT_BLOCK_SIZE);
        memcpy(M, plaintext + i * GIFT_BLOCK_SIZE, block_len);

        if (block_len < GIFT_BLOCK_SIZE) {
            M[block_len] = 0x80;
        }

        byte_t X[GIFT_BLOCK_SIZE];
        byte_t C[GIFT_BLOCK_SIZE];
        rho_function(ctx.Y, M, X, C, block_len);

        memcpy(ciphertext + i * GIFT_BLOCK_SIZE, C, block_len);

        uint64_t mask = compute_mask(ctx.delta, ad_blocks + i, (block_len < GIFT_BLOCK_SIZE) ? 1 : 0);
        xor_mask(X, mask);

        gift_encrypt_block(&ctx.gift, X, ctx.Y);
    }

    /* Generate tag */
    uint64_t final_mask = compute_mask(ctx.delta, ad_blocks + msg_blocks, 1);
    xor_mask(ctx.Y, final_mask);

    memcpy(tag, ctx.Y, GIFT_TAG_SIZE);

    memset(&ctx, 0, sizeof(ctx));
    return GIFT_SUCCESS;
}

/* GIFT-COFB decryption */
int gift_cofb_decrypt(
    const byte_t *key,
    const byte_t *nonce,
    const byte_t *ad, size_t ad_len,
    const byte_t *ciphertext, size_t ciphertext_len,
    const byte_t *tag,
    byte_t *plaintext)
{
    gift_cofb_ctx_t ctx;

    if (gift_cofb_init(&ctx, key, nonce) != GIFT_SUCCESS) {
        return GIFT_ERR_INVALID;
    }

    /* Process associated data */
    size_t ad_blocks = (ad_len + GIFT_BLOCK_SIZE - 1) / GIFT_BLOCK_SIZE;
    for (size_t i = 0; i < ad_blocks; i++) {
        size_t block_len = (i == ad_blocks - 1 && ad_len % GIFT_BLOCK_SIZE != 0)
                          ? ad_len % GIFT_BLOCK_SIZE
                          : GIFT_BLOCK_SIZE;

        byte_t ad_block[GIFT_BLOCK_SIZE];
        memset(ad_block, 0, GIFT_BLOCK_SIZE);
        memcpy(ad_block, ad + i * GIFT_BLOCK_SIZE, block_len);

        if (block_len < GIFT_BLOCK_SIZE) {
            ad_block[block_len] = 0x80;
        }

        byte_t X[GIFT_BLOCK_SIZE];
        rho_function(ctx.Y, ad_block, X, NULL, block_len);

        uint64_t mask = compute_mask(ctx.delta, i, (block_len < GIFT_BLOCK_SIZE) ? 1 : 0);
        xor_mask(X, mask);

        gift_encrypt_block(&ctx.gift, X, ctx.Y);
    }

    /* Process ciphertext */
    size_t msg_blocks = (ciphertext_len + GIFT_BLOCK_SIZE - 1) / GIFT_BLOCK_SIZE;
    if (ciphertext_len == 0) msg_blocks = 0;

    for (size_t i = 0; i < msg_blocks; i++) {
        size_t block_len = (i == msg_blocks - 1 && ciphertext_len % GIFT_BLOCK_SIZE != 0)
                          ? ciphertext_len % GIFT_BLOCK_SIZE
                          : GIFT_BLOCK_SIZE;

        byte_t C[GIFT_BLOCK_SIZE];
        memset(C, 0, GIFT_BLOCK_SIZE);
        memcpy(C, ciphertext + i * GIFT_BLOCK_SIZE, block_len);

        byte_t X[GIFT_BLOCK_SIZE];
        byte_t M[GIFT_BLOCK_SIZE];
        rho_inverse(ctx.Y, C, X, M, block_len);

        if (block_len < GIFT_BLOCK_SIZE) {
            X[block_len] = X[block_len] ^ 0x80;
        }

        memcpy(plaintext + i * GIFT_BLOCK_SIZE, M, block_len);

        uint64_t mask = compute_mask(ctx.delta, ad_blocks + i, (block_len < GIFT_BLOCK_SIZE) ? 1 : 0);
        xor_mask(X, mask);

        gift_encrypt_block(&ctx.gift, X, ctx.Y);
    }

    /* Verify tag */
    uint64_t final_mask = compute_mask(ctx.delta, ad_blocks + msg_blocks, 1);
    xor_mask(ctx.Y, final_mask);

    int auth_result = secure_compare(tag, ctx.Y, GIFT_TAG_SIZE);

    memset(&ctx, 0, sizeof(ctx));

    if (auth_result != 0) {
        memset(plaintext, 0, ciphertext_len);
        return GIFT_ERR_AUTH;
    }

    return GIFT_SUCCESS;
}
