#include "include/gfrx_cofb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void generate_random_nonce(byte_t *nonce, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(nonce, 1, len, f);
        fclose(f);
    } else {
        srand(time(NULL));
        for (size_t i = 0; i < len; i++) {
            nonce[i] = rand() & 0xFF;
        }
    }
}

static void print_usage(const char *prog) {
    printf("Usage: %s <command> <input> <key_hex> [ad_string]\n\n", prog);
    printf("Commands:\n");
    printf("  encrypt    Cifrar archivo\n");
    printf("  decrypt    Descifrar archivo\n\n");
    printf("Key format: 32 hex chars (128 bits)\n");
    printf("AD (optional): Associated Data (authenticated but not encrypted)\n\n");
    printf("Examples:\n");
    printf("  %s encrypt file.txt 0123456789abcdef0123456789abcdef\n", prog);
    printf("  %s encrypt file.txt 0123456789abcdef0123456789abcdef \"user:alice,file:secret.txt\"\n", prog);
}

static int hex_to_bytes(const char *hex, byte_t *bytes, size_t len) {
    if (strlen(hex) != len * 2) return -1;
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        bytes[i] = (byte_t)byte;
    }
    return 0;
}

static byte_t* read_file(const char *filename, size_t *size) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("Error opening file");
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);

    byte_t *data = malloc(*size);
    if (!data) {
        fclose(f);
        return NULL;
    }

    if (fread(data, 1, *size, f) != *size) {
        free(data);
        fclose(f);
        return NULL;
    }

    fclose(f);
    return data;
}

static int write_file(const char *filename, const byte_t *data, size_t size) {
    FILE *f = fopen(filename, "wb");
    if (!f) {
        perror("Error writing file");
        return -1;
    }

    if (fwrite(data, 1, size, f) != size) {
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 4 || argc > 5) {
        print_usage(argv[0]);
        return 1;
    }

    const char *command = argv[1];
    const char *input_file = argv[2];
    const char *key_hex = argv[3];
    const char *ad_string = (argc == 5) ? argv[4] : NULL;

    byte_t *ad = NULL;
    size_t ad_len = 0;
    if (ad_string) {
        ad = (byte_t *)ad_string;
        ad_len = strlen(ad_string);
    }

    byte_t key[GFRX_KEY_SIZE];
    if (hex_to_bytes(key_hex, key, GFRX_KEY_SIZE) != 0) {
        fprintf(stderr, "Error: Invalid key format (need 32 hex chars)\n");
        return 1;
    }

    if (strcmp(command, "encrypt") == 0) {
        size_t plaintext_len;
        byte_t *plaintext = read_file(input_file, &plaintext_len);
        if (!plaintext) return 1;

        byte_t nonce[GFRX_NONCE_SIZE];
        generate_random_nonce(nonce, GFRX_NONCE_SIZE);

        byte_t *ciphertext = malloc(plaintext_len);
        byte_t tag[GFRX_TAG_SIZE];

        if (cofb_encrypt(key, nonce, ad, ad_len, plaintext, plaintext_len,
                        ciphertext, tag) != GFRX_SUCCESS) {
            fprintf(stderr, "Error: Encryption failed\n");
            free(plaintext);
            free(ciphertext);
            return 1;
        }

        char output_file[256];
        snprintf(output_file, sizeof(output_file), "%s.enc", input_file);

        FILE *f = fopen(output_file, "wb");
        if (!f) {
            perror("Error creating output file");
            free(plaintext);
            free(ciphertext);
            return 1;
        }

        uint16_t ad_len_u16 = (uint16_t)ad_len;
        fwrite(&ad_len_u16, sizeof(uint16_t), 1, f);
        if (ad_len > 0) {
            fwrite(ad, 1, ad_len, f);
        }
        fwrite(nonce, 1, GFRX_NONCE_SIZE, f);
        fwrite(tag, 1, GFRX_TAG_SIZE, f);
        fwrite(ciphertext, 1, plaintext_len, f);
        fclose(f);

        printf("Encrypted: %s -> %s\n", input_file, output_file);
        if (ad_len > 0) {
            printf("AD: %s\n", ad_string);
        }
        printf("Size: %zu bytes\n", plaintext_len);

        free(plaintext);
        free(ciphertext);

    } else if (strcmp(command, "decrypt") == 0) {
        size_t encrypted_len;
        byte_t *encrypted = read_file(input_file, &encrypted_len);
        if (!encrypted) return 1;

        if (encrypted_len < sizeof(uint16_t) + GFRX_NONCE_SIZE + GFRX_TAG_SIZE) {
            fprintf(stderr, "Error: File too small\n");
            free(encrypted);
            return 1;
        }

        size_t offset = 0;
        uint16_t file_ad_len;
        memcpy(&file_ad_len, encrypted + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);

        byte_t *file_ad = NULL;
        if (file_ad_len > 0) {
            if (encrypted_len < offset + file_ad_len + GFRX_NONCE_SIZE + GFRX_TAG_SIZE) {
                fprintf(stderr, "Error: File corrupted (invalid AD length)\n");
                free(encrypted);
                return 1;
            }
            file_ad = encrypted + offset;
            offset += file_ad_len;
        }

        byte_t nonce[GFRX_NONCE_SIZE];
        byte_t tag[GFRX_TAG_SIZE];
        memcpy(nonce, encrypted + offset, GFRX_NONCE_SIZE);
        offset += GFRX_NONCE_SIZE;
        memcpy(tag, encrypted + offset, GFRX_TAG_SIZE);
        offset += GFRX_TAG_SIZE;

        size_t ciphertext_len = encrypted_len - offset;
        byte_t *ciphertext = encrypted + offset;
        byte_t *plaintext = malloc(ciphertext_len);

        if (cofb_decrypt(key, nonce, file_ad, file_ad_len, ciphertext, ciphertext_len,
                        tag, plaintext) != GFRX_SUCCESS) {
            fprintf(stderr, "Error: Decryption failed (wrong key or corrupted file)\n");
            free(encrypted);
            free(plaintext);
            return 1;
        }

        char output_file[256];
        const char *enc_ext = strstr(input_file, ".enc");
        if (enc_ext) {
            size_t base_len = enc_ext - input_file;
            snprintf(output_file, sizeof(output_file), "%.*s.dec", (int)base_len, input_file);
        } else {
            snprintf(output_file, sizeof(output_file), "%s.dec", input_file);
        }

        if (write_file(output_file, plaintext, ciphertext_len) != 0) {
            free(encrypted);
            free(plaintext);
            return 1;
        }

        printf("Decrypted: %s -> %s\n", input_file, output_file);
        if (file_ad_len > 0) {
            printf("AD: %.*s\n", (int)file_ad_len, file_ad);
        }
        printf("Size: %zu bytes\n", ciphertext_len);

        free(encrypted);
        free(plaintext);

    } else {
        fprintf(stderr, "Error: Unknown command '%s'\n", command);
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
