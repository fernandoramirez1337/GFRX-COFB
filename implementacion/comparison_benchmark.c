/**
 * AEAD Comparison Benchmark
 * Compares GFRX+COFB vs GIFT-COFB vs ASCON-128 vs AES-128-GCM
 *
 * Metrics measured:
 * - Throughput (Mbps) for different message sizes
 * - Latency (microseconds per operation)
 * - Memory footprint (state size in bits)
 */

#define _POSIX_C_SOURCE 199309L

#include "gfrx_cofb.h"
#include "gift_cofb.h"
#include "ascon.h"
#include "aes_gcm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#define WARMUP_ITERATIONS  1000
#define MIN_ITERATIONS     1000
#define MIN_TIME_SEC       1.0

/* Test message sizes (in bytes) */
static const size_t TEST_SIZES[] = {16, 64, 256, 1024, 4096, 16384};
static const size_t NUM_SIZES = sizeof(TEST_SIZES) / sizeof(TEST_SIZES[0]);

/* Benchmark result structure */
typedef struct {
    double throughput_mbps;
    double latency_us;
    size_t iterations;
} benchmark_result_t;

/* Results storage for analysis */
typedef struct {
    benchmark_result_t gfrx[6];
    benchmark_result_t gift[6];
    benchmark_result_t ascon[6];
    benchmark_result_t aes[6];
} all_results_t;

/* Get current time in seconds */
static double get_time(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Benchmark GFRX+COFB encryption */
static benchmark_result_t benchmark_gfrx_cofb(size_t msg_size) {
    byte_t key[GFRX_KEY_SIZE] = {0};
    byte_t nonce[GFRX_NONCE_SIZE] = {0};
    byte_t *plaintext = malloc(msg_size);
    byte_t *ciphertext = malloc(msg_size);
    byte_t tag[GFRX_TAG_SIZE];

    /* Initialize test data */
    for (size_t i = 0; i < msg_size; i++) {
        plaintext[i] = i & 0xFF;
    }

    /* Warmup */
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        nonce[0] = i & 0xFF;
        cofb_encrypt(key, nonce, NULL, 0, plaintext, msg_size, ciphertext, tag);
    }

    /* Actual benchmark - run for at least MIN_TIME_SEC */
    size_t iterations = 0;
    double start_time = get_time();
    double elapsed = 0.0;

    while (elapsed < MIN_TIME_SEC || iterations < MIN_ITERATIONS) {
        nonce[0] = iterations & 0xFF;
        cofb_encrypt(key, nonce, NULL, 0, plaintext, msg_size, ciphertext, tag);
        iterations++;
        elapsed = get_time() - start_time;
    }

    free(plaintext);
    free(ciphertext);

    benchmark_result_t result;
    result.iterations = iterations;
    result.latency_us = (elapsed / iterations) * 1e6;
    result.throughput_mbps = (iterations * msg_size * 8) / (elapsed * 1e6);

    return result;
}

/* Benchmark GIFT-COFB encryption */
static benchmark_result_t benchmark_gift_cofb(size_t msg_size) {
    byte_t key[GIFT_KEY_SIZE] = {0};
    byte_t nonce[GIFT_NONCE_SIZE] = {0};
    byte_t *plaintext = malloc(msg_size);
    byte_t *ciphertext = malloc(msg_size);
    byte_t tag[GIFT_TAG_SIZE];

    /* Initialize test data */
    for (size_t i = 0; i < msg_size; i++) {
        plaintext[i] = i & 0xFF;
    }

    /* Warmup */
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        nonce[0] = i & 0xFF;
        gift_cofb_encrypt(key, nonce, NULL, 0, plaintext, msg_size, ciphertext, tag);
    }

    /* Actual benchmark */
    size_t iterations = 0;
    double start_time = get_time();
    double elapsed = 0.0;

    while (elapsed < MIN_TIME_SEC || iterations < MIN_ITERATIONS) {
        nonce[0] = iterations & 0xFF;
        gift_cofb_encrypt(key, nonce, NULL, 0, plaintext, msg_size, ciphertext, tag);
        iterations++;
        elapsed = get_time() - start_time;
    }

    free(plaintext);
    free(ciphertext);

    benchmark_result_t result;
    result.iterations = iterations;
    result.latency_us = (elapsed / iterations) * 1e6;
    result.throughput_mbps = (iterations * msg_size * 8) / (elapsed * 1e6);

    return result;
}

/* Benchmark ASCON-128 encryption */
static benchmark_result_t benchmark_ascon(size_t msg_size) {
    byte_t key[ASCON_KEY_SIZE] = {0};
    byte_t nonce[ASCON_NONCE_SIZE] = {0};
    byte_t *plaintext = malloc(msg_size);
    byte_t *ciphertext = malloc(msg_size);
    byte_t tag[ASCON_TAG_SIZE];

    for (size_t i = 0; i < msg_size; i++) {
        plaintext[i] = i & 0xFF;
    }

    /* Warmup */
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        nonce[0] = i & 0xFF;
        ascon_encrypt(key, nonce, NULL, 0, plaintext, msg_size, ciphertext, tag);
    }

    /* Actual benchmark */
    size_t iterations = 0;
    double start_time = get_time();
    double elapsed = 0.0;

    while (elapsed < MIN_TIME_SEC || iterations < MIN_ITERATIONS) {
        nonce[0] = iterations & 0xFF;
        ascon_encrypt(key, nonce, NULL, 0, plaintext, msg_size, ciphertext, tag);
        iterations++;
        elapsed = get_time() - start_time;
    }

    free(plaintext);
    free(ciphertext);

    benchmark_result_t result;
    result.iterations = iterations;
    result.latency_us = (elapsed / iterations) * 1e6;
    result.throughput_mbps = (iterations * msg_size * 8) / (elapsed * 1e6);

    return result;
}

/* Benchmark AES-128-GCM encryption */
static benchmark_result_t benchmark_aes_gcm(size_t msg_size) {
    byte_t key[AES_KEY_SIZE] = {0};
    byte_t nonce[AES_NONCE_SIZE] = {0};
    byte_t *plaintext = malloc(msg_size);
    byte_t *ciphertext = malloc(msg_size);
    byte_t tag[AES_TAG_SIZE];

    for (size_t i = 0; i < msg_size; i++) {
        plaintext[i] = i & 0xFF;
    }

    /* Warmup */
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        nonce[0] = i & 0xFF;
        aes_gcm_encrypt(key, nonce, NULL, 0, plaintext, msg_size, ciphertext, tag);
    }

    /* Actual benchmark */
    size_t iterations = 0;
    double start_time = get_time();
    double elapsed = 0.0;

    while (elapsed < MIN_TIME_SEC || iterations < MIN_ITERATIONS) {
        nonce[0] = iterations & 0xFF;
        aes_gcm_encrypt(key, nonce, NULL, 0, plaintext, msg_size, ciphertext, tag);
        iterations++;
        elapsed = get_time() - start_time;
    }

    free(plaintext);
    free(ciphertext);

    benchmark_result_t result;
    result.iterations = iterations;
    result.latency_us = (elapsed / iterations) * 1e6;
    result.throughput_mbps = (iterations * msg_size * 8) / (elapsed * 1e6);

    return result;
}

/* Print header */
static void print_header(void) {
    printf("\n");
    printf("===============================================================================\n");
    printf("  AEAD Performance Comparison: GFRX+COFB vs GIFT-COFB vs ASCON vs AES-GCM\n");
    printf("===============================================================================\n");
    printf("\n");
}

/* Print characteristics table */
static void print_characteristics(void) {
    printf("Algorithm Characteristics:\n");
    printf("-------------------------------------------------------------------------------\n");
    printf("Scheme          State     Key       Nonce     Primitive Type\n");
    printf("-------------------------------------------------------------------------------\n");
    printf("GFRX+COFB       320 bits  128 bits   64 bits  Feistel ARX\n");
    printf("GIFT-COFB       320 bits  128 bits   64 bits  SPN (GIFT-128)\n");
    printf("ASCON-128       320 bits  128 bits  128 bits  Sponge permutation\n");
    printf("AES-128-GCM     384 bits  128 bits   96 bits  SPN (AES-128)\n");
    printf("-------------------------------------------------------------------------------\n");
    printf("\n");
}

/* Print comparison table for a specific size */
static void print_comparison(size_t msg_size,
                            benchmark_result_t gfrx,
                            benchmark_result_t gift,
                            benchmark_result_t ascon,
                            benchmark_result_t aes) {
    printf("Message Size: %zu bytes\n", msg_size);
    printf("-------------------------------------------------------------------------------\n");
    printf("Scheme           Throughput (Mbps)  Latency (us)   Iterations\n");
    printf("-------------------------------------------------------------------------------\n");
    printf("GFRX+COFB        %17.2f  %12.3f  %11zu\n",
           gfrx.throughput_mbps, gfrx.latency_us, gfrx.iterations);
    printf("GIFT-COFB        %17.2f  %12.3f  %11zu\n",
           gift.throughput_mbps, gift.latency_us, gift.iterations);
    printf("ASCON-128        %17.2f  %12.3f  %11zu\n",
           ascon.throughput_mbps, ascon.latency_us, ascon.iterations);
    printf("AES-128-GCM      %17.2f  %12.3f  %11zu\n",
           aes.throughput_mbps, aes.latency_us, aes.iterations);
    printf("-------------------------------------------------------------------------------\n");
    printf("\n");
}

/* Print benchmark completion */
static void print_summary(const all_results_t *results) {
    (void)results;  /* Unused */
    printf("Benchmark completed.\n");
}

/* Main benchmark function */
int main(void) {
    all_results_t results;

    print_header();
    print_characteristics();

    printf("Running benchmarks (each test runs for minimum %.1f second)...\n\n", MIN_TIME_SEC);

    for (size_t i = 0; i < NUM_SIZES; i++) {
        size_t size = TEST_SIZES[i];

        results.gfrx[i] = benchmark_gfrx_cofb(size);
        results.gift[i] = benchmark_gift_cofb(size);
        results.ascon[i] = benchmark_ascon(size);
        results.aes[i] = benchmark_aes_gcm(size);

        print_comparison(size, results.gfrx[i], results.gift[i],
                        results.ascon[i], results.aes[i]);
    }

    print_summary(&results);

    return 0;
}
