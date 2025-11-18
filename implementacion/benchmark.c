#include "include/gfrx_cofb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ITERATIONS 100000

static double benchmark_gfrx_encrypt(int iterations) {
    byte_t key[GFRX_KEY_SIZE];
    byte_t plaintext[GFRX_BLOCK_SIZE];
    byte_t ciphertext[GFRX_BLOCK_SIZE];

    for (int i = 0; i < GFRX_KEY_SIZE; i++) key[i] = i;
    for (int i = 0; i < GFRX_BLOCK_SIZE; i++) plaintext[i] = i;

    gfrx_ctx_t ctx;
    gfrx_init(&ctx, key);

    clock_t start = clock();
    for (int i = 0; i < iterations; i++) {
        gfrx_encrypt_block(&ctx, plaintext, ciphertext);
    }
    clock_t end = clock();

    return ((double)(end - start)) / CLOCKS_PER_SEC;
}

static double benchmark_gfrx_decrypt(int iterations) {
    byte_t key[GFRX_KEY_SIZE];
    byte_t plaintext[GFRX_BLOCK_SIZE];
    byte_t ciphertext[GFRX_BLOCK_SIZE];

    for (int i = 0; i < GFRX_KEY_SIZE; i++) key[i] = i;
    for (int i = 0; i < GFRX_BLOCK_SIZE; i++) ciphertext[i] = i;

    gfrx_ctx_t ctx;
    gfrx_init(&ctx, key);

    clock_t start = clock();
    for (int i = 0; i < iterations; i++) {
        gfrx_decrypt_block(&ctx, ciphertext, plaintext);
    }
    clock_t end = clock();

    return ((double)(end - start)) / CLOCKS_PER_SEC;
}

static double benchmark_cofb_encrypt(int iterations, size_t msg_size) {
    byte_t key[GFRX_KEY_SIZE];
    byte_t nonce[GFRX_NONCE_SIZE];
    byte_t *plaintext = malloc(msg_size);
    byte_t *ciphertext = malloc(msg_size);
    byte_t tag[GFRX_TAG_SIZE];

    for (int i = 0; i < GFRX_KEY_SIZE; i++) key[i] = i;
    for (size_t i = 0; i < msg_size; i++) plaintext[i] = i & 0xFF;

    clock_t start = clock();
    for (int i = 0; i < iterations; i++) {
        for (int j = 0; j < GFRX_NONCE_SIZE; j++) nonce[j] = (i >> j) & 0xFF;
        cofb_encrypt(key, nonce, NULL, 0, plaintext, msg_size, ciphertext, tag);
    }
    clock_t end = clock();

    free(plaintext);
    free(ciphertext);

    return ((double)(end - start)) / CLOCKS_PER_SEC;
}

static double benchmark_cofb_decrypt(int iterations, size_t msg_size) {
    byte_t key[GFRX_KEY_SIZE];
    byte_t nonce[GFRX_NONCE_SIZE];
    byte_t *plaintext = malloc(msg_size);
    byte_t *ciphertext = malloc(msg_size);
    byte_t *decrypted = malloc(msg_size);
    byte_t tag[GFRX_TAG_SIZE];

    for (int i = 0; i < GFRX_KEY_SIZE; i++) key[i] = i;
    for (int j = 0; j < GFRX_NONCE_SIZE; j++) nonce[j] = j;
    for (size_t i = 0; i < msg_size; i++) plaintext[i] = i & 0xFF;

    cofb_encrypt(key, nonce, NULL, 0, plaintext, msg_size, ciphertext, tag);

    clock_t start = clock();
    for (int i = 0; i < iterations; i++) {
        cofb_decrypt(key, nonce, NULL, 0, ciphertext, msg_size, tag, decrypted);
    }
    clock_t end = clock();

    free(plaintext);
    free(ciphertext);
    free(decrypted);

    return ((double)(end - start)) / CLOCKS_PER_SEC;
}

int main() {
    printf("GFRX+COFB Benchmarks\n\n");

    printf("GFRX Block Cipher:\n");

    double time_encrypt = benchmark_gfrx_encrypt(ITERATIONS);
    double blocks_per_sec = ITERATIONS / time_encrypt;
    double mbps_encrypt = (blocks_per_sec * GFRX_BLOCK_SIZE * 8) / 1000000.0;

    printf("  Encrypt: %.2f Mbps (%.2f us/op)\n", mbps_encrypt, (time_encrypt * 1000000) / ITERATIONS);

    double time_decrypt = benchmark_gfrx_decrypt(ITERATIONS);
    blocks_per_sec = ITERATIONS / time_decrypt;
    double mbps_decrypt = (blocks_per_sec * GFRX_BLOCK_SIZE * 8) / 1000000.0;

    printf("  Decrypt: %.2f Mbps (%.2f us/op)\n\n", mbps_decrypt, (time_decrypt * 1000000) / ITERATIONS);

    printf("COFB Mode:\n");

    size_t sizes[] = {16, 64, 256, 1024, 4096};
    int iters[] = {50000, 20000, 10000, 5000, 1000};

    for (size_t i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
        size_t size = sizes[i];
        int iter = iters[i];

        double time = benchmark_cofb_encrypt(iter, size);
        double mbps = (iter / time * size * 8) / 1000000.0;
        printf("  %4zu bytes: %.2f Mbps encrypt", size, mbps);

        time = benchmark_cofb_decrypt(iter, size);
        mbps = (iter / time * size * 8) / 1000000.0;
        printf(", %.2f Mbps decrypt\n", mbps);
    }

    return 0;
}
