/**
 * GIFT-128 Block Cipher Implementation
 * Based on GIFT specification (Banik et al., 2017)
 * https://giftcipher.github.io/gift/
 */

#include "gift_cofb.h"

/* GIFT-128 S-box (4-bit) */
static const uint8_t GIFT_SBOX[16] = {
    0x1, 0xa, 0x4, 0xc, 0x6, 0xf, 0x3, 0x9,
    0x2, 0xd, 0xb, 0x7, 0x5, 0x0, 0x8, 0xe
};

/* GIFT-128 Inverse S-box */
static const uint8_t GIFT_SBOX_INV[16] = {
    0xd, 0x0, 0x8, 0x6, 0x2, 0xc, 0x4, 0xb,
    0xe, 0x7, 0x1, 0xa, 0x3, 0x9, 0xf, 0x5
};

/* Bit permutation for GIFT-128 */
static const uint8_t GIFT_PERM[128] = {
      0,  33,  66,  99,  96,   1,  34,  67,
     64,  97,   2,  35,  32,  65,  98,   3,
      4,  37,  70, 103, 100,   5,  38,  71,
     68, 101,   6,  39,  36,  69, 102,   7,
      8,  41,  74, 107, 104,   9,  42,  75,
     72, 105,  10,  43,  40,  73, 106,  11,
     12,  45,  78, 111, 108,  13,  46,  79,
     76, 109,  14,  47,  44,  77, 110,  15,
     16,  49,  82, 115, 112,  17,  50,  83,
     80, 113,  18,  51,  48,  81, 114,  19,
     20,  53,  86, 119, 116,  21,  54,  87,
     84, 117,  22,  55,  52,  85, 118,  23,
     24,  57,  90, 123, 120,  25,  58,  91,
     88, 121,  26,  59,  56,  89, 122,  27,
     28,  61,  94, 127, 124,  29,  62,  95,
     92, 125,  30,  63,  60,  93, 126,  31
};

/* Inverse bit permutation */
static const uint8_t GIFT_PERM_INV[128] = {
      0,   5,  10,  15,  16,  21,  26,  31,
     32,  37,  42,  47,  48,  53,  58,  63,
     64,  69,  74,  79,  80,  85,  90,  95,
     96, 101, 106, 111, 112, 117, 122, 127,
     12,   1,   6,  11,  28,  17,  22,  27,
     44,  33,  38,  43,  60,  49,  54,  59,
     76,  65,  70,  75,  92,  81,  86,  91,
    108,  97, 102, 107, 124, 113, 118, 123,
      8,  13,   2,   7,  24,  29,  18,  23,
     40,  45,  34,  39,  56,  61,  50,  55,
     72,  77,  66,  71,  88,  93,  82,  87,
    104, 109,  98, 103, 120, 125, 114, 119,
      4,   9,  14,   3,  20,  25,  30,  19,
     36,  41,  46,  35,  52,  57,  62,  51,
     68,  73,  78,  67,  84,  89,  94,  83,
    100, 105, 110,  99, 116, 121, 126, 115
};

/* Round constants for GIFT-128 (first 6 bits) */
static const uint8_t GIFT_RC[40] = {
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B,
    0x37, 0x2F, 0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E,
    0x1D, 0x3A, 0x35, 0x2B, 0x16, 0x2C, 0x18, 0x30,
    0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E, 0x1C, 0x38,
    0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A
};

/* Helper: Get bit from state */
static inline uint8_t get_bit(const word32_t *state, int pos) {
    int word_idx = pos / 32;
    int bit_idx = pos % 32;
    return (state[word_idx] >> bit_idx) & 1;
}

/* Helper: Set bit in state */
static inline void set_bit(word32_t *state, int pos, uint8_t val) {
    int word_idx = pos / 32;
    int bit_idx = pos % 32;
    if (val) {
        state[word_idx] |= (1U << bit_idx);
    } else {
        state[word_idx] &= ~(1U << bit_idx);
    }
}

/* SubCells: Apply S-box to all 4-bit nibbles */
static void gift_subcells(word32_t *state) {
    for (int i = 0; i < 4; i++) {
        word32_t w = state[i];
        word32_t result = 0;

        for (int j = 0; j < 8; j++) {
            uint8_t nibble = (w >> (j * 4)) & 0xF;
            uint8_t sbox_out = GIFT_SBOX[nibble];
            result |= ((word32_t)sbox_out) << (j * 4);
        }

        state[i] = result;
    }
}

/* Inverse SubCells */
static void gift_subcells_inv(word32_t *state) {
    for (int i = 0; i < 4; i++) {
        word32_t w = state[i];
        word32_t result = 0;

        for (int j = 0; j < 8; j++) {
            uint8_t nibble = (w >> (j * 4)) & 0xF;
            uint8_t sbox_out = GIFT_SBOX_INV[nibble];
            result |= ((word32_t)sbox_out) << (j * 4);
        }

        state[i] = result;
    }
}

/* PermBits: Bit permutation */
static void gift_permbits(word32_t *state) {
    word32_t temp[4] = {0, 0, 0, 0};

    for (int i = 0; i < 128; i++) {
        uint8_t bit = get_bit(state, i);
        set_bit(temp, GIFT_PERM[i], bit);
    }

    memcpy(state, temp, sizeof(temp));
}

/* Inverse PermBits */
static void gift_permbits_inv(word32_t *state) {
    word32_t temp[4] = {0, 0, 0, 0};

    for (int i = 0; i < 128; i++) {
        uint8_t bit = get_bit(state, i);
        set_bit(temp, GIFT_PERM_INV[i], bit);
    }

    memcpy(state, temp, sizeof(temp));
}

/* AddRoundKey: XOR with round key and round constant */
static void gift_addroundkey(word32_t *state, const word32_t *rk, uint8_t rc) {
    /* XOR round key with specific bits */
    state[1] ^= rk[0];  /* U */
    state[2] ^= rk[1];  /* V */

    /* Add round constant to specific bits */
    state[3] ^= (rc & 0x3F);  /* Lower 6 bits of RC */
    state[0] ^= ((rc & 0x40) >> 6) << 3;  /* Bit 6 of RC */
}

/* Key schedule for GIFT-128 */
static void gift_key_schedule(gift_ctx_t *ctx, const byte_t *key) {
    /* Load key into two 64-bit words (represented as pairs of 32-bit) */
    word32_t k0 = ((word32_t)key[0]) | ((word32_t)key[1] << 8) |
                  ((word32_t)key[2] << 16) | ((word32_t)key[3] << 24);
    word32_t k1 = ((word32_t)key[4]) | ((word32_t)key[5] << 8) |
                  ((word32_t)key[6] << 16) | ((word32_t)key[7] << 24);
    word32_t k2 = ((word32_t)key[8]) | ((word32_t)key[9] << 8) |
                  ((word32_t)key[10] << 16) | ((word32_t)key[11] << 24);
    word32_t k3 = ((word32_t)key[12]) | ((word32_t)key[13] << 8) |
                  ((word32_t)key[14] << 16) | ((word32_t)key[15] << 24);

    for (int i = 0; i < GIFT_ROUNDS; i++) {
        /* Extract round key from current key state */
        ctx->round_keys[2 * i] = k1;      /* U */
        ctx->round_keys[2 * i + 1] = k2;  /* V */

        /* Update key state */
        word32_t temp = k3;
        k3 = k2;
        k2 = k1;
        k1 = k0;

        /* Rotate and update k0 */
        k0 = ((temp >> 2) | (temp << 30)) & 0xFFFFFFFF;
    }
}

/* Initialize GIFT-128 context */
int gift_init(gift_ctx_t *ctx, const byte_t *key) {
    if (!ctx || !key) {
        return GIFT_ERR_INVALID;
    }

    memset(ctx, 0, sizeof(gift_ctx_t));
    gift_key_schedule(ctx, key);

    return GIFT_SUCCESS;
}

/* Load 128-bit block into state */
static void load_block(word32_t *state, const byte_t *block) {
    for (int i = 0; i < 4; i++) {
        state[i] = ((word32_t)block[4*i]) |
                   ((word32_t)block[4*i + 1] << 8) |
                   ((word32_t)block[4*i + 2] << 16) |
                   ((word32_t)block[4*i + 3] << 24);
    }
}

/* Store state into 128-bit block */
static void store_block(byte_t *block, const word32_t *state) {
    for (int i = 0; i < 4; i++) {
        block[4*i] = state[i] & 0xFF;
        block[4*i + 1] = (state[i] >> 8) & 0xFF;
        block[4*i + 2] = (state[i] >> 16) & 0xFF;
        block[4*i + 3] = (state[i] >> 24) & 0xFF;
    }
}

/* GIFT-128 encryption */
void gift_encrypt_block(const gift_ctx_t *ctx, const byte_t *plaintext, byte_t *ciphertext) {
    word32_t state[4];

    load_block(state, plaintext);

    for (int round = 0; round < GIFT_ROUNDS; round++) {
        gift_subcells(state);
        gift_permbits(state);
        gift_addroundkey(state, &ctx->round_keys[2 * round], GIFT_RC[round]);
    }

    store_block(ciphertext, state);
}

/* GIFT-128 decryption */
void gift_decrypt_block(const gift_ctx_t *ctx, const byte_t *ciphertext, byte_t *plaintext) {
    word32_t state[4];

    load_block(state, ciphertext);

    for (int round = GIFT_ROUNDS - 1; round >= 0; round--) {
        gift_addroundkey(state, &ctx->round_keys[2 * round], GIFT_RC[round]);
        gift_permbits_inv(state);
        gift_subcells_inv(state);
    }

    store_block(plaintext, state);
}
