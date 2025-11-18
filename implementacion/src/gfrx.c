#include "../include/gfrx_cofb.h"
#include <stdio.h>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static inline word32_t FAN(word32_t x0, word32_t x1, word32_t key) {
    word32_t t1 = ROTL32(x1, 1);
    word32_t t8 = ROTL32(x1, 8);
    word32_t t2 = ROTL32(x1, 2);
    return (t1 & t8) ^ x0 ^ t2 ^ key;
}

static inline word32_t FADL(word32_t x, word32_t y) {
    return ROTL32((x + y) & 0xFFFFFFFF, 8);
}

static inline word32_t FADR(word32_t x, word32_t y) {
    return ROTL32(x ^ y, 3);
}

static inline word32_t FADL_INV(word32_t x, word32_t y) {
    word32_t temp = ROTR32(x, 8);
    return (temp - y) & 0xFFFFFFFF;
}

static inline word32_t FADR_INV(word32_t x, word32_t y) {
    return ROTR32(x, 3) ^ y;
}

static void gfrx_key_schedule(word32_t *round_keys, const byte_t *key) {
    word32_t K[4];
    for (int i = 0; i < 4; i++) {
        K[i] = ((word32_t)key[i*4 + 0]) |
               ((word32_t)key[i*4 + 1] << 8) |
               ((word32_t)key[i*4 + 2] << 16) |
               ((word32_t)key[i*4 + 3] << 24);
    }

    word32_t L0 = K[0], L1 = K[1];
    word32_t R0 = K[2], R1 = K[3];

    for (int r = 0; r < GFRX_ROUNDS; r++) {
        round_keys[r*4 + 0] = L0;
        round_keys[r*4 + 1] = L1;
        round_keys[r*4 + 2] = R0;
        round_keys[r*4 + 3] = R1;

        word32_t state0 = FAN(L0, L1, r);
        word32_t state1 = FADL(L1, R0) ^ (r << 16);
        word32_t state2 = FADR(R0, state1);
        word32_t state3 = FAN(R1, R0, r + 0x12345678);

        L0 = state1;
        L1 = state3;
        R0 = state0;
        R1 = state2;
    }
}

static void gfrx_round_encrypt(word32_t *state, const word32_t *round_key) {
    word32_t L0 = state[0], L1 = state[1];
    word32_t R0 = state[2], R1 = state[3];

    word32_t state0 = FAN(L0, L1, round_key[0]);
    word32_t state1 = FADL(L1, R0) ^ round_key[1];
    word32_t state2 = FADR(R0, state1);
    word32_t state3 = FAN(R1, R0, round_key[2]);

    state[0] = state1;
    state[1] = state3;
    state[2] = state0;
    state[3] = state2;
}

static void gfrx_round_decrypt(word32_t *state, const word32_t *round_key) {
    word32_t state1 = state[0];
    word32_t state3 = state[1];
    word32_t state0 = state[2];
    word32_t state2 = state[3];

    word32_t R0 = FADR_INV(state2, state1);
    word32_t L1 = FADL_INV(state1 ^ round_key[1], R0);

    word32_t t1 = ROTL32(L1, 1);
    word32_t t8 = ROTL32(L1, 8);
    word32_t t2 = ROTL32(L1, 2);
    word32_t L0 = state0 ^ (t1 & t8) ^ t2 ^ round_key[0];

    t1 = ROTL32(R0, 1);
    t8 = ROTL32(R0, 8);
    t2 = ROTL32(R0, 2);
    word32_t R1 = state3 ^ (t1 & t8) ^ t2 ^ round_key[2];

    state[0] = L0;
    state[1] = L1;
    state[2] = R0;
    state[3] = R1;
}

int gfrx_init(gfrx_ctx_t *ctx, const byte_t *key) {
    if (!ctx || !key) {
        return GFRX_ERR_INVALID;
    }
    gfrx_key_schedule(ctx->round_keys, key);
    memset(ctx->state, 0, sizeof(ctx->state));
    return GFRX_SUCCESS;
}

void gfrx_encrypt_block(const gfrx_ctx_t *ctx, const byte_t *plaintext, byte_t *ciphertext) {
    word32_t state[4];
    for (int i = 0; i < 4; i++) {
        state[i] = ((word32_t)plaintext[i*4 + 0]) |
                   ((word32_t)plaintext[i*4 + 1] << 8) |
                   ((word32_t)plaintext[i*4 + 2] << 16) |
                   ((word32_t)plaintext[i*4 + 3] << 24);
    }
    for (int r = 0; r < GFRX_ROUNDS; r++) {
        gfrx_round_encrypt(state, &ctx->round_keys[r * 4]);
    }
    for (int i = 0; i < 4; i++) {
        ciphertext[i*4 + 0] = (state[i] >> 0) & 0xFF;
        ciphertext[i*4 + 1] = (state[i] >> 8) & 0xFF;
        ciphertext[i*4 + 2] = (state[i] >> 16) & 0xFF;
        ciphertext[i*4 + 3] = (state[i] >> 24) & 0xFF;
    }
}

void gfrx_decrypt_block(const gfrx_ctx_t *ctx, const byte_t *ciphertext, byte_t *plaintext) {
    word32_t state[4];
    for (int i = 0; i < 4; i++) {
        state[i] = ((word32_t)ciphertext[i*4 + 0]) |
                   ((word32_t)ciphertext[i*4 + 1] << 8) |
                   ((word32_t)ciphertext[i*4 + 2] << 16) |
                   ((word32_t)ciphertext[i*4 + 3] << 24);
    }
    for (int r = GFRX_ROUNDS - 1; r >= 0; r--) {
        gfrx_round_decrypt(state, &ctx->round_keys[r * 4]);
    }
    for (int i = 0; i < 4; i++) {
        plaintext[i*4 + 0] = (state[i] >> 0) & 0xFF;
        plaintext[i*4 + 1] = (state[i] >> 8) & 0xFF;
        plaintext[i*4 + 2] = (state[i] >> 16) & 0xFF;
        plaintext[i*4 + 3] = (state[i] >> 24) & 0xFF;
    }
}
