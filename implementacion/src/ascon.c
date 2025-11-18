/**
 * ASCON-128 AEAD Implementation
 * Based on ASCON v1.2 specification
 * https://ascon.iaik.tugraz.at/
 */

#include "ascon.h"
#include <string.h>

/* ASCON-128 IV */
#define ASCON_IV 0x80400c0600000000ULL

/* Rotation macros */
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

/* Load 64-bit big-endian */
static inline word64_t load64(const byte_t *bytes) {
    word64_t x = 0;
    for (int i = 0; i < 8; i++) {
        x = (x << 8) | bytes[i];
    }
    return x;
}

/* Store 64-bit big-endian */
static inline void store64(byte_t *bytes, word64_t x) {
    for (int i = 7; i >= 0; i--) {
        bytes[i] = x & 0xff;
        x >>= 8;
    }
}

/* Addition of constants */
static inline void ascon_add_constant(ascon_state_t *s, uint8_t c) {
    s->x[2] ^= c;
}

/* Substitution layer */
static void ascon_sbox(ascon_state_t *s) {
    s->x[0] ^= s->x[4];
    s->x[4] ^= s->x[3];
    s->x[2] ^= s->x[1];

    word64_t t[5];
    t[0] = s->x[0] ^ (~s->x[1] & s->x[2]);
    t[1] = s->x[1] ^ (~s->x[2] & s->x[3]);
    t[2] = s->x[2] ^ (~s->x[3] & s->x[4]);
    t[3] = s->x[3] ^ (~s->x[4] & s->x[0]);
    t[4] = s->x[4] ^ (~s->x[0] & s->x[1]);

    t[1] ^= t[0];
    t[0] ^= t[4];
    t[3] ^= t[2];
    t[2] = ~t[2];

    for (int i = 0; i < 5; i++) {
        s->x[i] = t[i];
    }
}

/* Linear diffusion layer */
static void ascon_linear(ascon_state_t *s) {
    word64_t t[5];

    t[0] = s->x[0] ^ ROTR64(s->x[0], 19) ^ ROTR64(s->x[0], 28);
    t[1] = s->x[1] ^ ROTR64(s->x[1], 61) ^ ROTR64(s->x[1], 39);
    t[2] = s->x[2] ^ ROTR64(s->x[2], 1)  ^ ROTR64(s->x[2], 6);
    t[3] = s->x[3] ^ ROTR64(s->x[3], 10) ^ ROTR64(s->x[3], 17);
    t[4] = s->x[4] ^ ROTR64(s->x[4], 7)  ^ ROTR64(s->x[4], 41);

    for (int i = 0; i < 5; i++) {
        s->x[i] = t[i];
    }
}

/* ASCON permutation */
static void ascon_permutation(ascon_state_t *s, int rounds) {
    int start_round = 12 - rounds;
    for (int i = start_round; i < 12; i++) {
        ascon_add_constant(s, (12 - i - 1) << 4 | i);
        ascon_sbox(s);
        ascon_linear(s);
    }
}

/* Initialize ASCON state */
static void ascon_init(ascon_state_t *s, const byte_t *key, const byte_t *nonce) {
    /* Initialize state: IV || K || N */
    s->x[0] = ASCON_IV;
    s->x[1] = load64(key);
    s->x[2] = load64(key + 8);
    s->x[3] = load64(nonce);
    s->x[4] = load64(nonce + 8);

    /* Initial permutation with 12 rounds */
    ascon_permutation(s, 12);

    /* Absorb key */
    s->x[3] ^= load64(key);
    s->x[4] ^= load64(key + 8);
}

/* Process associated data */
static void ascon_process_ad(ascon_state_t *s, const byte_t *ad, size_t ad_len) {
    if (ad_len == 0) {
        s->x[4] ^= 1; /* Domain separation for empty AD */
        return;
    }

    /* Process full blocks */
    while (ad_len >= ASCON_RATE) {
        s->x[0] ^= load64(ad);
        ascon_permutation(s, 6);
        ad += ASCON_RATE;
        ad_len -= ASCON_RATE;
    }

    /* Process final incomplete block */
    if (ad_len > 0) {
        byte_t padded[ASCON_RATE] = {0};
        memcpy(padded, ad, ad_len);
        padded[ad_len] = 0x80; /* Padding */
        s->x[0] ^= load64(padded);
        ascon_permutation(s, 6);
    } else {
        s->x[0] ^= 0x8000000000000000ULL; /* Padding for full block */
        ascon_permutation(s, 6);
    }

    /* Domain separation */
    s->x[4] ^= 1;
}

/* ASCON-128 encryption */
int ascon_encrypt(
    const byte_t *key,
    const byte_t *nonce,
    const byte_t *ad, size_t ad_len,
    const byte_t *plaintext, size_t pt_len,
    byte_t *ciphertext,
    byte_t *tag)
{
    ascon_state_t s;

    /* Initialization */
    ascon_init(&s, key, nonce);

    /* Process associated data */
    ascon_process_ad(&s, ad, ad_len);

    /* Process plaintext */
    size_t remaining = pt_len;
    const byte_t *pt = plaintext;
    byte_t *ct = ciphertext;

    while (remaining >= ASCON_RATE) {
        word64_t pt_word = load64(pt);
        word64_t ct_word = s.x[0] ^ pt_word;
        store64(ct, ct_word);
        s.x[0] = ct_word;
        ascon_permutation(&s, 6);
        pt += ASCON_RATE;
        ct += ASCON_RATE;
        remaining -= ASCON_RATE;
    }

    /* Process final incomplete block */
    if (remaining > 0) {
        byte_t padded[ASCON_RATE] = {0};
        memcpy(padded, pt, remaining);
        padded[remaining] = 0x80;

        word64_t pt_word = load64(padded);
        word64_t ct_word = s.x[0] ^ pt_word;

        byte_t ct_bytes[ASCON_RATE];
        store64(ct_bytes, ct_word);
        memcpy(ct, ct_bytes, remaining);

        /* Update state with ciphertext */
        memcpy(padded, ct_bytes, remaining);
        padded[remaining] = 0x80;
        s.x[0] = load64(padded);
    } else if (pt_len > 0) {
        s.x[0] ^= 0x8000000000000000ULL;
    }

    /* Finalization */
    s.x[1] ^= load64(key);
    s.x[2] ^= load64(key + 8);
    ascon_permutation(&s, 12);
    s.x[3] ^= load64(key);
    s.x[4] ^= load64(key + 8);

    /* Generate tag */
    store64(tag, s.x[3]);
    store64(tag + 8, s.x[4]);

    /* Clear sensitive data */
    memset(&s, 0, sizeof(s));

    return ASCON_SUCCESS;
}

/* ASCON-128 decryption */
int ascon_decrypt(
    const byte_t *key,
    const byte_t *nonce,
    const byte_t *ad, size_t ad_len,
    const byte_t *ciphertext, size_t ct_len,
    const byte_t *tag,
    byte_t *plaintext)
{
    ascon_state_t s;

    /* Initialization */
    ascon_init(&s, key, nonce);

    /* Process associated data */
    ascon_process_ad(&s, ad, ad_len);

    /* Process ciphertext */
    size_t remaining = ct_len;
    const byte_t *ct = ciphertext;
    byte_t *pt = plaintext;

    while (remaining >= ASCON_RATE) {
        word64_t ct_word = load64(ct);
        word64_t pt_word = s.x[0] ^ ct_word;
        store64(pt, pt_word);
        s.x[0] = ct_word;
        ascon_permutation(&s, 6);
        ct += ASCON_RATE;
        pt += ASCON_RATE;
        remaining -= ASCON_RATE;
    }

    /* Process final incomplete block */
    if (remaining > 0) {
        byte_t ct_padded[ASCON_RATE] = {0};
        memcpy(ct_padded, ct, remaining);

        byte_t state_bytes[ASCON_RATE];
        store64(state_bytes, s.x[0]);

        for (size_t i = 0; i < remaining; i++) {
            pt[i] = state_bytes[i] ^ ct_padded[i];
        }

        /* Update state */
        memcpy(ct_padded, ct, remaining);
        ct_padded[remaining] = 0x80;
        s.x[0] = load64(ct_padded);
    } else if (ct_len > 0) {
        s.x[0] ^= 0x8000000000000000ULL;
    }

    /* Finalization */
    s.x[1] ^= load64(key);
    s.x[2] ^= load64(key + 8);
    ascon_permutation(&s, 12);
    s.x[3] ^= load64(key);
    s.x[4] ^= load64(key + 8);

    /* Verify tag */
    byte_t computed_tag[ASCON_TAG_SIZE];
    store64(computed_tag, s.x[3]);
    store64(computed_tag + 8, s.x[4]);

    int result = ASCON_SUCCESS;
    for (int i = 0; i < ASCON_TAG_SIZE; i++) {
        if (computed_tag[i] != tag[i]) {
            result = ASCON_ERR_AUTH;
        }
    }

    /* Clear sensitive data */
    memset(&s, 0, sizeof(s));

    if (result != ASCON_SUCCESS) {
        memset(plaintext, 0, ct_len);
    }

    return result;
}
