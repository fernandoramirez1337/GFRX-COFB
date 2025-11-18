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
    printf("GFRX+COFB Demo\n\n");

    byte_t key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    byte_t nonce[8] = {0,1,2,3,4,5,6,7};
    byte_t plaintext[] = "Hola desde GFRX-COFB";
    size_t len = strlen((char*)plaintext);

    byte_t ciphertext[100], tag[16], decrypted[100];

    printf("Mensaje: \"%s\" (%zu bytes)\n", plaintext, len);

    if (cofb_encrypt(key, nonce, NULL, 0, plaintext, len, ciphertext, tag) == GFRX_SUCCESS) {
        print_hex("Ciphertext", ciphertext, len);
        print_hex("Tag       ", tag, 16);
    }

    if (cofb_decrypt(key, nonce, NULL, 0, ciphertext, len, tag, decrypted) == GFRX_SUCCESS) {
        decrypted[len] = '\0';
        printf("Decrypted: \"%s\"\n", decrypted);
    }

    tag[0] ^= 0x01;
    if (cofb_decrypt(key, nonce, NULL, 0, ciphertext, len, tag, decrypted) == GFRX_ERR_AUTH) {
        printf("Auth check: OK\n");
    }

    printf("\nDemo con AD:\n");
    byte_t ad[] = "Usuario: alice@example.com";
    size_t ad_len = strlen((char*)ad);
    byte_t mensaje[] = "Saldo: $10000";
    size_t msg_len = strlen((char*)mensaje);
    byte_t ciphertext2[100], tag2[16], decrypted2[100];

    printf("AD: %s\n", ad);
    printf("Mensaje: %s\n", mensaje);

    cofb_encrypt(key, nonce, ad, ad_len, mensaje, msg_len, ciphertext2, tag2);
    print_hex("Ciphertext", ciphertext2, msg_len);

    if (cofb_decrypt(key, nonce, ad, ad_len, ciphertext2, msg_len, tag2, decrypted2) == GFRX_SUCCESS) {
        decrypted2[msg_len] = '\0';
        printf("Decrypted: %s\n", decrypted2);
    }

    ad[0] = 'X';
    if (cofb_decrypt(key, nonce, ad, ad_len, ciphertext2, msg_len, tag2, decrypted2) == GFRX_ERR_AUTH) {
        printf("Auth check (modified AD): OK\n");
    }

    return 0;
}
