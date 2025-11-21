#include "include/gfrx_cofb.h"
#include <stdio.h>
#include <string.h>

static void print_hex(const char *label, const byte_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    printf("# GFRX+COFB Test Vectors\n");
    printf("# Generated for reproducibility and validation\n\n");

    // Test Vector 1: GFRX Block Cipher
    printf("## Test Vector 1: GFRX-128 Block Cipher\n\n");
    {
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
        gfrx_init(&ctx, key);
        gfrx_encrypt_block(&ctx, plaintext, ciphertext);
        gfrx_decrypt_block(&ctx, ciphertext, decrypted);

        print_hex("Key       ", key, GFRX_KEY_SIZE);
        print_hex("Plaintext ", plaintext, GFRX_BLOCK_SIZE);
        print_hex("Ciphertext", ciphertext, GFRX_BLOCK_SIZE);
        print_hex("Decrypted ", decrypted, GFRX_BLOCK_SIZE);
        printf("\n");
    }

    // Test Vector 2: COFB Empty Message
    printf("## Test Vector 2: COFB Empty Message\n\n");
    {
        byte_t key[GFRX_KEY_SIZE] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        byte_t nonce[GFRX_NONCE_SIZE] = {
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
        };
        byte_t tag[GFRX_TAG_SIZE];

        cofb_encrypt(key, nonce, NULL, 0, NULL, 0, NULL, tag);

        print_hex("Key   ", key, GFRX_KEY_SIZE);
        print_hex("Nonce ", nonce, GFRX_NONCE_SIZE);
        printf("AD Length    : 0\n");
        printf("Message Length: 0\n");
        print_hex("Tag   ", tag, GFRX_TAG_SIZE);
        printf("\n");
    }

    // Test Vector 3: COFB with Small Message
    printf("## Test Vector 3: COFB with 8-byte Message\n\n");
    {
        byte_t key[GFRX_KEY_SIZE] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        byte_t nonce[GFRX_NONCE_SIZE] = {
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
        };
        byte_t plaintext[8] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
        byte_t ciphertext[8];
        byte_t tag[GFRX_TAG_SIZE];

        cofb_encrypt(key, nonce, NULL, 0, plaintext, 8, ciphertext, tag);

        print_hex("Key       ", key, GFRX_KEY_SIZE);
        print_hex("Nonce     ", nonce, GFRX_NONCE_SIZE);
        printf("AD Length    : 0\n");
        printf("Message Length: 8\n");
        print_hex("Plaintext ", plaintext, 8);
        print_hex("Ciphertext", ciphertext, 8);
        print_hex("Tag       ", tag, GFRX_TAG_SIZE);
        printf("\n");
    }

    // Test Vector 4: COFB with 16-byte Message (One Block)
    printf("## Test Vector 4: COFB with 16-byte Message (One Block)\n\n");
    {
        byte_t key[GFRX_KEY_SIZE] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        byte_t nonce[GFRX_NONCE_SIZE] = {
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
        };
        byte_t plaintext[16];
        byte_t ciphertext[16];
        byte_t tag[GFRX_TAG_SIZE];

        for (int i = 0; i < 16; i++) plaintext[i] = i;
        cofb_encrypt(key, nonce, NULL, 0, plaintext, 16, ciphertext, tag);

        print_hex("Key       ", key, GFRX_KEY_SIZE);
        print_hex("Nonce     ", nonce, GFRX_NONCE_SIZE);
        printf("AD Length    : 0\n");
        printf("Message Length: 16\n");
        print_hex("Plaintext ", plaintext, 16);
        print_hex("Ciphertext", ciphertext, 16);
        print_hex("Tag       ", tag, GFRX_TAG_SIZE);
        printf("\n");
    }

    // Test Vector 5: COFB with 64-byte Message (Four Blocks)
    printf("## Test Vector 5: COFB with 64-byte Message (Four Blocks)\n\n");
    {
        byte_t key[GFRX_KEY_SIZE] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        byte_t nonce[GFRX_NONCE_SIZE] = {
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
        };
        byte_t plaintext[64];
        byte_t ciphertext[64];
        byte_t tag[GFRX_TAG_SIZE];

        for (int i = 0; i < 64; i++) plaintext[i] = i;
        cofb_encrypt(key, nonce, NULL, 0, plaintext, 64, ciphertext, tag);

        print_hex("Key       ", key, GFRX_KEY_SIZE);
        print_hex("Nonce     ", nonce, GFRX_NONCE_SIZE);
        printf("AD Length    : 0\n");
        printf("Message Length: 64\n");
        print_hex("Plaintext ", plaintext, 64);
        print_hex("Ciphertext", ciphertext, 64);
        print_hex("Tag       ", tag, GFRX_TAG_SIZE);
        printf("\n");
    }

    // Test Vector 6: COFB with Associated Data
    printf("## Test Vector 6: COFB with Associated Data\n\n");
    {
        byte_t key[GFRX_KEY_SIZE] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        byte_t nonce[GFRX_NONCE_SIZE] = {
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57
        };
        byte_t ad[16];
        byte_t plaintext[32];
        byte_t ciphertext[32];
        byte_t tag[GFRX_TAG_SIZE];

        for (int i = 0; i < 16; i++) ad[i] = 0xAA + i;
        for (int i = 0; i < 32; i++) plaintext[i] = i;
        cofb_encrypt(key, nonce, ad, 16, plaintext, 32, ciphertext, tag);

        print_hex("Key       ", key, GFRX_KEY_SIZE);
        print_hex("Nonce     ", nonce, GFRX_NONCE_SIZE);
        printf("AD Length    : 16\n");
        print_hex("AD        ", ad, 16);
        printf("Message Length: 32\n");
        print_hex("Plaintext ", plaintext, 32);
        print_hex("Ciphertext", ciphertext, 32);
        print_hex("Tag       ", tag, GFRX_TAG_SIZE);
        printf("\n");
    }

    // Test Vector 7: COFB with Text Message
    printf("## Test Vector 7: COFB with Text Message\n\n");
    {
        byte_t key[GFRX_KEY_SIZE] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        byte_t nonce[GFRX_NONCE_SIZE] = {
            0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67
        };
        byte_t plaintext[] = "Hello, GFRX+COFB!";
        size_t plaintext_len = strlen((char *)plaintext);
        byte_t ciphertext[100];
        byte_t tag[GFRX_TAG_SIZE];

        cofb_encrypt(key, nonce, NULL, 0, plaintext, plaintext_len, ciphertext, tag);

        print_hex("Key       ", key, GFRX_KEY_SIZE);
        print_hex("Nonce     ", nonce, GFRX_NONCE_SIZE);
        printf("AD Length    : 0\n");
        printf("Message Length: %zu\n", plaintext_len);
        printf("Plaintext : \"%s\"\n", (char *)plaintext);
        print_hex("Ciphertext", ciphertext, plaintext_len);
        print_hex("Tag       ", tag, GFRX_TAG_SIZE);
        printf("\n");
    }

    // Test Vector 8: All-Zero Key and Nonce
    printf("## Test Vector 8: All-Zero Key and Nonce\n\n");
    {
        byte_t key[GFRX_KEY_SIZE] = {0};
        byte_t nonce[GFRX_NONCE_SIZE] = {0};
        byte_t plaintext[16] = {0};
        byte_t ciphertext[16];
        byte_t tag[GFRX_TAG_SIZE];

        cofb_encrypt(key, nonce, NULL, 0, plaintext, 16, ciphertext, tag);

        print_hex("Key       ", key, GFRX_KEY_SIZE);
        print_hex("Nonce     ", nonce, GFRX_NONCE_SIZE);
        printf("AD Length    : 0\n");
        printf("Message Length: 16\n");
        print_hex("Plaintext ", plaintext, 16);
        print_hex("Ciphertext", ciphertext, 16);
        print_hex("Tag       ", tag, GFRX_TAG_SIZE);
        printf("\n");
    }

    // Test Vector 9: All-FF Key and Message
    printf("## Test Vector 9: All-FF Key and Message\n\n");
    {
        byte_t key[GFRX_KEY_SIZE];
        byte_t nonce[GFRX_NONCE_SIZE];
        byte_t plaintext[16];
        byte_t ciphertext[16];
        byte_t tag[GFRX_TAG_SIZE];

        memset(key, 0xFF, GFRX_KEY_SIZE);
        memset(nonce, 0xFF, GFRX_NONCE_SIZE);
        memset(plaintext, 0xFF, 16);

        cofb_encrypt(key, nonce, NULL, 0, plaintext, 16, ciphertext, tag);

        print_hex("Key       ", key, GFRX_KEY_SIZE);
        print_hex("Nonce     ", nonce, GFRX_NONCE_SIZE);
        printf("AD Length    : 0\n");
        printf("Message Length: 16\n");
        print_hex("Plaintext ", plaintext, 16);
        print_hex("Ciphertext", ciphertext, 16);
        print_hex("Tag       ", tag, GFRX_TAG_SIZE);
        printf("\n");
    }

    // Test Vector 10: Long Message (256 bytes)
    printf("## Test Vector 10: Long Message (256 bytes)\n\n");
    {
        byte_t key[GFRX_KEY_SIZE] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        byte_t nonce[GFRX_NONCE_SIZE] = {
            0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77
        };
        byte_t plaintext[256];
        byte_t ciphertext[256];
        byte_t tag[GFRX_TAG_SIZE];

        for (int i = 0; i < 256; i++) plaintext[i] = i & 0xFF;
        cofb_encrypt(key, nonce, NULL, 0, plaintext, 256, ciphertext, tag);

        print_hex("Key       ", key, GFRX_KEY_SIZE);
        print_hex("Nonce     ", nonce, GFRX_NONCE_SIZE);
        printf("AD Length    : 0\n");
        printf("Message Length: 256\n");
        printf("Plaintext : 00 01 02 03 ... FE FF (sequential bytes)\n");
        print_hex("Ciphertext", ciphertext, 256);
        print_hex("Tag       ", tag, GFRX_TAG_SIZE);
        printf("\n");
    }

    printf("# End of Test Vectors\n");
    return 0;
}
