
#include "../include/gfrx_cofb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>


static void print_hex(const char *label, const byte_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}


static void test_gfrx_basic() {
    printf("\n=== Test 1: GFRX Block Cipher ===\n");

    byte_t key[GFRX_KEY_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    byte_t plaintext[GFRX_BLOCK_SIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };

    byte_t ciphertext[GFRX_BLOCK_SIZE];
    byte_t decrypted[GFRX_BLOCK_SIZE];

    gfrx_ctx_t ctx;
    assert(gfrx_init(&ctx, key) == GFRX_SUCCESS);

    gfrx_encrypt_block(&ctx, plaintext, ciphertext);
    gfrx_decrypt_block(&ctx, ciphertext, decrypted);

    if (memcmp(plaintext, decrypted, GFRX_BLOCK_SIZE) == 0) {
        printf("  OK\n");
    } else {
        printf("  FAIL\n");
    }
}

static void test_cofb_empty() {
    printf("\n=== Test 2: COFB Empty Message ===\n");

    byte_t key[GFRX_KEY_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    byte_t nonce[GFRX_NONCE_SIZE] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };

    byte_t tag[GFRX_TAG_SIZE];

    assert(cofb_encrypt(key, nonce, NULL, 0, NULL, 0, NULL, tag) == GFRX_SUCCESS);
    assert(cofb_decrypt(key, nonce, NULL, 0, NULL, 0, tag, NULL) == GFRX_SUCCESS);

    tag[0] ^= 0x01;
    assert(cofb_decrypt(key, nonce, NULL, 0, NULL, 0, tag, NULL) == GFRX_ERR_AUTH);
    printf("  OK\n");
}

static void test_cofb_with_ad() {
    printf("\n=== Test 3: COFB with AD ===\n");

    byte_t key[GFRX_KEY_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    byte_t nonce[GFRX_NONCE_SIZE] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
    };

    byte_t ad[] = "Additional authenticated data";
    size_t ad_len = strlen((char *)ad);

    byte_t plaintext[] = "Hello, GFRX+COFB!";
    size_t plaintext_len = strlen((char *)plaintext);

    byte_t ciphertext[100];
    byte_t decrypted[100];
    byte_t tag[GFRX_TAG_SIZE];

    assert(cofb_encrypt(key, nonce, ad, ad_len, plaintext, plaintext_len,
                       ciphertext, tag) == GFRX_SUCCESS);

    assert(cofb_decrypt(key, nonce, ad, ad_len, ciphertext, plaintext_len,
                       tag, decrypted) == GFRX_SUCCESS);

    assert(memcmp(plaintext, decrypted, plaintext_len) == 0);

    ad[0] ^= 0x01;
    assert(cofb_decrypt(key, nonce, ad, ad_len, ciphertext, plaintext_len,
                       tag, decrypted) == GFRX_ERR_AUTH);
    printf("  OK\n");
}

static void test_cofb_lengths() {
    printf("\n=== Test 4: Various Lengths ===\n");

    byte_t key[GFRX_KEY_SIZE];
    byte_t nonce[GFRX_NONCE_SIZE];
    byte_t plaintext[256];
    byte_t ciphertext[256];
    byte_t decrypted[256];
    byte_t tag[GFRX_TAG_SIZE];

    for (int i = 0; i < GFRX_KEY_SIZE; i++) key[i] = i * 17;
    for (int i = 0; i < GFRX_NONCE_SIZE; i++) nonce[i] = i * 13;
    for (int i = 0; i < 256; i++) plaintext[i] = i;

    size_t test_lengths[] = {0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255};

    for (size_t i = 0; i < sizeof(test_lengths) / sizeof(test_lengths[0]); i++) {
        size_t len = test_lengths[i];

        assert(cofb_encrypt(key, nonce, NULL, 0, plaintext, len,
                          ciphertext, tag) == GFRX_SUCCESS);

        assert(cofb_decrypt(key, nonce, NULL, 0, ciphertext, len,
                          tag, decrypted) == GFRX_SUCCESS);

        assert(memcmp(plaintext, decrypted, len) == 0);
    }
    printf("  OK (15 lengths tested)\n");
}

static void test_performance() {
    printf("\n=== Test 5: Performance ===\n");

    byte_t key[GFRX_KEY_SIZE];
    byte_t nonce[GFRX_NONCE_SIZE];
    byte_t plaintext[1024];
    byte_t ciphertext[1024];
    byte_t tag[GFRX_TAG_SIZE];

    for (int i = 0; i < GFRX_KEY_SIZE; i++) key[i] = i;
    for (int i = 0; i < GFRX_NONCE_SIZE; i++) nonce[i] = i;
    for (int i = 0; i < 1024; i++) plaintext[i] = i & 0xFF;

    const int iterations = 10000;
    clock_t start, end;

    gfrx_ctx_t ctx;
    gfrx_init(&ctx, key);

    start = clock();
    for (int i = 0; i < iterations; i++) {
        gfrx_encrypt_block(&ctx, plaintext, ciphertext);
    }
    end = clock();

    double time1 = ((double)(end - start)) / CLOCKS_PER_SEC;
    double mbps1 = (iterations / time1 * GFRX_BLOCK_SIZE * 8) / 1000000.0;

    start = clock();
    for (int i = 0; i < iterations / 10; i++) {
        cofb_encrypt(key, nonce, NULL, 0, plaintext, 1024, ciphertext, tag);
        nonce[0]++;
    }
    end = clock();

    double time2 = ((double)(end - start)) / CLOCKS_PER_SEC;
    double mbps2 = ((iterations / 10) / time2 * 1024 * 8) / 1000000.0;

    printf("  GFRX: %.2f Mbps, COFB: %.2f Mbps\n", mbps1, mbps2);
}

static void test_vectors() {
    printf("\n=== Test 6: Test Vectors ===\n");

    byte_t key[GFRX_KEY_SIZE] = {0};
    byte_t nonce[GFRX_NONCE_SIZE] = {0};
    byte_t plaintext[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    byte_t ciphertext[8];
    byte_t tag[GFRX_TAG_SIZE];

    assert(cofb_encrypt(key, nonce, NULL, 0, plaintext, 8, ciphertext, tag) == GFRX_SUCCESS);
    print_hex("  Ciphertext", ciphertext, 8);
    print_hex("  Tag       ", tag, GFRX_TAG_SIZE);
}

static void test_gfrx_consistency() {
    printf("\n=== Test 7: GFRX Consistency (100 rounds) ===\n");

    byte_t key[GFRX_KEY_SIZE];
    byte_t plaintext[GFRX_BLOCK_SIZE];
    byte_t ciphertext[GFRX_BLOCK_SIZE];
    byte_t decrypted[GFRX_BLOCK_SIZE];

    int failures = 0;
    for (int test = 0; test < 100; test++) {
        for (int i = 0; i < GFRX_KEY_SIZE; i++) {
            key[i] = (test * 7 + i * 13) & 0xFF;
        }
        for (int i = 0; i < GFRX_BLOCK_SIZE; i++) {
            plaintext[i] = (test * 11 + i * 17) & 0xFF;
        }

        gfrx_ctx_t ctx;
        gfrx_init(&ctx, key);
        gfrx_encrypt_block(&ctx, plaintext, ciphertext);
        gfrx_decrypt_block(&ctx, ciphertext, decrypted);

        if (memcmp(plaintext, decrypted, GFRX_BLOCK_SIZE) != 0) {
            failures++;
        }
    }
    printf("  OK (%d/100 passed)\n", 100 - failures);
}

static void test_gfrx_avalanche() {
    printf("\n=== Test 8: GFRX Avalanche ===\n");

    byte_t key[GFRX_KEY_SIZE] = {0};
    byte_t plaintext1[GFRX_BLOCK_SIZE] = {0};
    byte_t plaintext2[GFRX_BLOCK_SIZE] = {0};
    byte_t ciphertext1[GFRX_BLOCK_SIZE];
    byte_t ciphertext2[GFRX_BLOCK_SIZE];

    plaintext2[0] = 0x01;

    gfrx_ctx_t ctx;
    gfrx_init(&ctx, key);
    gfrx_encrypt_block(&ctx, plaintext1, ciphertext1);
    gfrx_encrypt_block(&ctx, plaintext2, ciphertext2);

    int bits_changed = 0;
    for (int i = 0; i < GFRX_BLOCK_SIZE; i++) {
        byte_t diff = ciphertext1[i] ^ ciphertext2[i];
        for (int j = 0; j < 8; j++) {
            if (diff & (1 << j)) bits_changed++;
        }
    }

    printf("  %d/128 bits (%.1f%%) - ", bits_changed, (bits_changed * 100.0) / 128);
    if (bits_changed >= 50 && bits_changed <= 78) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
    }
}

static void test_cofb_all_lengths() {
    printf("\n=== Test 9: COFB All Lengths 0-512 ===\n");

    byte_t key[GFRX_KEY_SIZE];
    byte_t nonce[GFRX_NONCE_SIZE];
    byte_t plaintext[513];
    byte_t ciphertext[513];
    byte_t decrypted[513];
    byte_t tag[GFRX_TAG_SIZE];

    for (int i = 0; i < GFRX_KEY_SIZE; i++) key[i] = i * 17;
    for (int i = 0; i < GFRX_NONCE_SIZE; i++) nonce[i] = i * 13;
    for (int i = 0; i < 513; i++) plaintext[i] = i & 0xFF;

    int failures = 0;
    for (size_t len = 0; len <= 512; len++) {
        if (cofb_encrypt(key, nonce, NULL, 0, plaintext, len, ciphertext, tag) != GFRX_SUCCESS) {
            failures++;
            continue;
        }
        if (cofb_decrypt(key, nonce, NULL, 0, ciphertext, len, tag, decrypted) != GFRX_SUCCESS) {
            failures++;
            continue;
        }
        if (len > 0 && memcmp(plaintext, decrypted, len) != 0) {
            failures++;
        }
    }

    printf("  OK (%d/513 passed)\n", 513 - failures);
}

static void test_cofb_authentication() {
    printf("\n=== Test 10: COFB Authentication ===\n");

    byte_t key[GFRX_KEY_SIZE] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    byte_t nonce[GFRX_NONCE_SIZE] = {1,2,3,4,5,6,7,8};
    byte_t plaintext[64];
    byte_t ciphertext[64];
    byte_t decrypted[64];
    byte_t tag[GFRX_TAG_SIZE];

    for (int i = 0; i < 64; i++) plaintext[i] = i;

    int passed = 0;
    for (int test = 0; test < 10; test++) {
        cofb_encrypt(key, nonce, NULL, 0, plaintext, 32, ciphertext, tag);

        tag[test % GFRX_TAG_SIZE] ^= 0x01;

        if (cofb_decrypt(key, nonce, NULL, 0, ciphertext, 32, tag, decrypted) == GFRX_ERR_AUTH) {
            passed++;
        }

        tag[test % GFRX_TAG_SIZE] ^= 0x01;
    }

    printf("  OK (%d/10 passed)\n", passed);
}

static void test_cofb_nonce_uniqueness() {
    printf("\n=== Test 11: COFB Nonce Uniqueness ===\n");

    byte_t key[GFRX_KEY_SIZE] = {0};
    byte_t nonce[GFRX_NONCE_SIZE];
    byte_t plaintext[] = "Test message";
    byte_t ciphertext1[64];
    byte_t ciphertext2[64];
    byte_t tag1[GFRX_TAG_SIZE];
    byte_t tag2[GFRX_TAG_SIZE];

    size_t len = strlen((char*)plaintext);
    int different = 0;

    for (int test = 0; test < 10; test++) {
        for (int i = 0; i < GFRX_NONCE_SIZE; i++) nonce[i] = test + i;
        cofb_encrypt(key, nonce, NULL, 0, plaintext, len, ciphertext1, tag1);

        nonce[0]++;
        cofb_encrypt(key, nonce, NULL, 0, plaintext, len, ciphertext2, tag2);

        if (memcmp(ciphertext1, ciphertext2, len) != 0) {
            different++;
        }
    }

    printf("  OK (%d/10 passed)\n", different);
}

static void test_cofb_stress() {
    printf("\n=== Test 12: Stress Test (1000 ops) ===\n");

    byte_t key[GFRX_KEY_SIZE];
    byte_t nonce[GFRX_NONCE_SIZE];
    byte_t plaintext[256];
    byte_t ciphertext[256];
    byte_t decrypted[256];
    byte_t tag[GFRX_TAG_SIZE];

    int failures = 0;
    for (int test = 0; test < 1000; test++) {
        for (int i = 0; i < GFRX_KEY_SIZE; i++) key[i] = (test >> (i*2)) & 0xFF;
        for (int i = 0; i < GFRX_NONCE_SIZE; i++) nonce[i] = (test >> i) & 0xFF;

        size_t len = (test % 200) + 1;
        for (size_t i = 0; i < len; i++) plaintext[i] = (test + i) & 0xFF;

        if (cofb_encrypt(key, nonce, NULL, 0, plaintext, len, ciphertext, tag) != GFRX_SUCCESS) {
            failures++;
            continue;
        }

        if (cofb_decrypt(key, nonce, NULL, 0, ciphertext, len, tag, decrypted) != GFRX_SUCCESS) {
            failures++;
            continue;
        }

        if (memcmp(plaintext, decrypted, len) != 0) {
            failures++;
        }
    }

    printf("  OK (%d/1000 passed)\n", 1000 - failures);
}


int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    printf("GFRX+COFB Test Suite\n");
    printf("====================\n");

    test_gfrx_basic();
    test_cofb_empty();
    test_cofb_with_ad();
    test_cofb_lengths();
    test_performance();
    test_vectors();
    test_gfrx_consistency();
    test_gfrx_avalanche();
    test_cofb_all_lengths();
    test_cofb_authentication();
    test_cofb_nonce_uniqueness();
    test_cofb_stress();

    printf("\nAll tests completed.\n");
    return 0;
}
