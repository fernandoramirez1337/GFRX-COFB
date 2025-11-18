#include "../include/gfrx_cofb.h"
#include <string.h>

int secure_compare(const byte_t *a, const byte_t *b, size_t len) {
    volatile byte_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result;
}

void secure_zero(void *ptr, size_t len) {
    volatile byte_t *p = (volatile byte_t *)ptr;
    for (size_t i = 0; i < len; i++) {
        p[i] = 0;
    }
    __asm__ __volatile__("" ::: "memory");
}
