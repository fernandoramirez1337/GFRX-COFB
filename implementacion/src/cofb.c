#include "../include/gfrx_cofb.h"
#include <stdio.h>
#include <stdlib.h>

#define POLY64 0x1B

static uint64_t compute_mask(uint64_t delta, int a, int b) {
    uint64_t mask = delta;
    for (int i = 0; i < a; i++) {
        uint64_t msb = mask >> 63;
        mask <<= 1;
        if (msb) {
            mask ^= POLY64;
        }
    }
    if (b == 1) {
        uint64_t temp = mask;
        uint64_t msb = mask >> 63;
        mask <<= 1;
        if (msb) {
            mask ^= POLY64;
        }
        mask ^= temp;
    }
    return mask;
}

static void G_function(const byte_t *Y, byte_t *result) {
    uint32_t Y1 = ((uint32_t)Y[0]) | ((uint32_t)Y[1] << 8) | 
                  ((uint32_t)Y[2] << 16) | ((uint32_t)Y[3] << 24);
    uint32_t Y2 = ((uint32_t)Y[4]) | ((uint32_t)Y[5] << 8) | 
                  ((uint32_t)Y[6] << 16) | ((uint32_t)Y[7] << 24);
    uint32_t Y3 = ((uint32_t)Y[8]) | ((uint32_t)Y[9] << 8) | 
                  ((uint32_t)Y[10] << 16) | ((uint32_t)Y[11] << 24);
    uint32_t Y4 = ((uint32_t)Y[12]) | ((uint32_t)Y[13] << 8) | 
                  ((uint32_t)Y[14] << 16) | ((uint32_t)Y[15] << 24);
    
    uint32_t G1 = Y2;
    uint32_t G2 = Y3;
    uint32_t G3 = Y4;
    uint32_t G4 = Y4 ^ Y1;
    
    result[0] = G1 & 0xFF; result[1] = (G1 >> 8) & 0xFF;
    result[2] = (G1 >> 16) & 0xFF; result[3] = (G1 >> 24) & 0xFF;
    result[4] = G2 & 0xFF; result[5] = (G2 >> 8) & 0xFF;
    result[6] = (G2 >> 16) & 0xFF; result[7] = (G2 >> 24) & 0xFF;
    result[8] = G3 & 0xFF; result[9] = (G3 >> 8) & 0xFF;
    result[10] = (G3 >> 16) & 0xFF; result[11] = (G3 >> 24) & 0xFF;
    result[12] = G4 & 0xFF; result[13] = (G4 >> 8) & 0xFF;
    result[14] = (G4 >> 16) & 0xFF; result[15] = (G4 >> 24) & 0xFF;
}

static void rho_function(const byte_t *Y, const byte_t *M, byte_t *X, byte_t *C, size_t len) {
    byte_t G_Y[GFRX_BLOCK_SIZE];
    G_function(Y, G_Y);
    
    for (size_t i = 0; i < len; i++) {
        X[i] = G_Y[i] ^ M[i];
    }
    for (size_t i = len; i < GFRX_BLOCK_SIZE; i++) {
        X[i] = G_Y[i];
    }
    
    if (C != NULL) {
        for (size_t i = 0; i < len; i++) {
            C[i] = Y[i] ^ M[i];
        }
    }
}

static void rho_inverse(const byte_t *Y, const byte_t *C, byte_t *X, byte_t *M, size_t len) {
    byte_t G_Y[GFRX_BLOCK_SIZE];
    byte_t M_padded[GFRX_BLOCK_SIZE];
    G_function(Y, G_Y);

    memset(M_padded, 0, GFRX_BLOCK_SIZE);
    for (size_t i = 0; i < len; i++) {
        M_padded[i] = Y[i] ^ C[i];
        if (M != NULL) {
            M[i] = M_padded[i];
        }
    }

    for (size_t i = 0; i < GFRX_BLOCK_SIZE; i++) {
        X[i] = G_Y[i] ^ M_padded[i];
    }
}

int cofb_init(cofb_ctx_t *ctx, const byte_t *key, const byte_t *nonce) {
    if (!ctx || !key || !nonce) {
        return GFRX_ERR_INVALID;
    }
    
    gfrx_init(&ctx->gfrx, key);
    
    byte_t nonce_block[GFRX_BLOCK_SIZE];
    memset(nonce_block, 0, GFRX_BLOCK_SIZE);
    memcpy(nonce_block, nonce, GFRX_NONCE_SIZE);
    
    gfrx_encrypt_block(&ctx->gfrx, nonce_block, ctx->Y);
    
    uint64_t delta = 0;
    for (int i = 0; i < 8; i++) {
        delta |= ((uint64_t)ctx->Y[i]) << (i * 8);
    }
    ctx->delta = delta;
    
    ctx->ad_blocks = 0;
    ctx->msg_blocks = 0;
    
    return GFRX_SUCCESS;
}

int cofb_encrypt(const byte_t *key, const byte_t *nonce,
                 const byte_t *ad, size_t ad_len,
                 const byte_t *plaintext, size_t plaintext_len,
                 byte_t *ciphertext, byte_t *tag) {
    
    cofb_ctx_t ctx;
    if (cofb_init(&ctx, key, nonce) != GFRX_SUCCESS) {
        return GFRX_ERR_INVALID;
    }
    
    byte_t Y[GFRX_BLOCK_SIZE];
    memcpy(Y, ctx.Y, GFRX_BLOCK_SIZE);
    
    size_t ad_blocks = 0;
    if (ad != NULL && ad_len > 0) {
        size_t remaining = ad_len;
        size_t offset = 0;
        
        while (remaining >= GFRX_BLOCK_SIZE) {
            byte_t X[GFRX_BLOCK_SIZE];
            rho_function(Y, ad + offset, X, NULL, GFRX_BLOCK_SIZE);
            
            byte_t L[GFRX_BLOCK_SIZE];
            memset(L, 0, GFRX_BLOCK_SIZE);
            uint64_t mask = compute_mask(ctx.delta, ad_blocks, 0);
            for (int i = 0; i < 8; i++) {
                L[i] = (mask >> (i * 8)) & 0xFF;
            }
            
            for (size_t i = 0; i < GFRX_BLOCK_SIZE; i++) {
                X[i] ^= L[i];
            }
            
            gfrx_encrypt_block(&ctx.gfrx, X, Y);
            
            offset += GFRX_BLOCK_SIZE;
            remaining -= GFRX_BLOCK_SIZE;
            ad_blocks++;
        }
        
        if (remaining > 0) {
            byte_t X[GFRX_BLOCK_SIZE];
            rho_function(Y, ad + offset, X, NULL, remaining);
            
            byte_t L[GFRX_BLOCK_SIZE];
            memset(L, 0, GFRX_BLOCK_SIZE);
            uint64_t mask = compute_mask(ctx.delta, ad_blocks, 1);
            for (int i = 0; i < 8; i++) {
                L[i] = (mask >> (i * 8)) & 0xFF;
            }
            
            for (size_t i = 0; i < GFRX_BLOCK_SIZE; i++) {
                X[i] ^= L[i];
            }
            
            gfrx_encrypt_block(&ctx.gfrx, X, Y);
            ad_blocks++;
        }
    }
    
    size_t msg_blocks = 0;
    if (plaintext != NULL && plaintext_len > 0) {
        size_t remaining = plaintext_len;
        size_t offset = 0;
        
        while (remaining >= GFRX_BLOCK_SIZE) {
            byte_t X[GFRX_BLOCK_SIZE];
            byte_t C[GFRX_BLOCK_SIZE];
            rho_function(Y, plaintext + offset, X, C, GFRX_BLOCK_SIZE);
            
            memcpy(ciphertext + offset, C, GFRX_BLOCK_SIZE);
            
            byte_t L[GFRX_BLOCK_SIZE];
            memset(L, 0, GFRX_BLOCK_SIZE);
            uint64_t mask = compute_mask(ctx.delta, ad_blocks + msg_blocks, 0);
            for (int i = 0; i < 8; i++) {
                L[i] = (mask >> (i * 8)) & 0xFF;
            }
            
            for (size_t i = 0; i < GFRX_BLOCK_SIZE; i++) {
                X[i] ^= L[i];
            }
            
            gfrx_encrypt_block(&ctx.gfrx, X, Y);
            
            offset += GFRX_BLOCK_SIZE;
            remaining -= GFRX_BLOCK_SIZE;
            msg_blocks++;
        }
        
        if (remaining > 0) {
            byte_t X[GFRX_BLOCK_SIZE];
            byte_t C[GFRX_BLOCK_SIZE];
            rho_function(Y, plaintext + offset, X, C, remaining);
            
            memcpy(ciphertext + offset, C, remaining);
            
            byte_t L[GFRX_BLOCK_SIZE];
            memset(L, 0, GFRX_BLOCK_SIZE);
            uint64_t mask = compute_mask(ctx.delta, ad_blocks + msg_blocks, 1);
            for (int i = 0; i < 8; i++) {
                L[i] = (mask >> (i * 8)) & 0xFF;
            }
            
            for (size_t i = 0; i < GFRX_BLOCK_SIZE; i++) {
                X[i] ^= L[i];
            }
            
            gfrx_encrypt_block(&ctx.gfrx, X, Y);
            msg_blocks++;
        }
    } else {
        byte_t X[GFRX_BLOCK_SIZE];
        byte_t G_Y[GFRX_BLOCK_SIZE];
        G_function(Y, G_Y);
        memcpy(X, G_Y, GFRX_BLOCK_SIZE);
        
        byte_t L[GFRX_BLOCK_SIZE];
        memset(L, 0, GFRX_BLOCK_SIZE);
        uint64_t mask = compute_mask(ctx.delta, ad_blocks, 1);
        for (int i = 0; i < 8; i++) {
            L[i] = (mask >> (i * 8)) & 0xFF;
        }
        
        for (size_t i = 0; i < GFRX_BLOCK_SIZE; i++) {
            X[i] ^= L[i];
        }
        
        gfrx_encrypt_block(&ctx.gfrx, X, Y);
    }
    
    memcpy(tag, Y, GFRX_TAG_SIZE);
    
    secure_zero(&ctx, sizeof(cofb_ctx_t));
    
    return GFRX_SUCCESS;
}

int cofb_decrypt(const byte_t *key, const byte_t *nonce,
                 const byte_t *ad, size_t ad_len,
                 const byte_t *ciphertext, size_t ciphertext_len,
                 const byte_t *tag, byte_t *plaintext) {
    
    cofb_ctx_t ctx;
    if (cofb_init(&ctx, key, nonce) != GFRX_SUCCESS) {
        return GFRX_ERR_INVALID;
    }
    
    byte_t Y[GFRX_BLOCK_SIZE];
    memcpy(Y, ctx.Y, GFRX_BLOCK_SIZE);
    
    size_t ad_blocks = 0;
    if (ad != NULL && ad_len > 0) {
        size_t remaining = ad_len;
        size_t offset = 0;
        
        while (remaining >= GFRX_BLOCK_SIZE) {
            byte_t X[GFRX_BLOCK_SIZE];
            rho_function(Y, ad + offset, X, NULL, GFRX_BLOCK_SIZE);
            
            byte_t L[GFRX_BLOCK_SIZE];
            memset(L, 0, GFRX_BLOCK_SIZE);
            uint64_t mask = compute_mask(ctx.delta, ad_blocks, 0);
            for (int i = 0; i < 8; i++) {
                L[i] = (mask >> (i * 8)) & 0xFF;
            }
            
            for (size_t i = 0; i < GFRX_BLOCK_SIZE; i++) {
                X[i] ^= L[i];
            }
            
            gfrx_encrypt_block(&ctx.gfrx, X, Y);
            
            offset += GFRX_BLOCK_SIZE;
            remaining -= GFRX_BLOCK_SIZE;
            ad_blocks++;
        }
        
        if (remaining > 0) {
            byte_t X[GFRX_BLOCK_SIZE];
            rho_function(Y, ad + offset, X, NULL, remaining);
            
            byte_t L[GFRX_BLOCK_SIZE];
            memset(L, 0, GFRX_BLOCK_SIZE);
            uint64_t mask = compute_mask(ctx.delta, ad_blocks, 1);
            for (int i = 0; i < 8; i++) {
                L[i] = (mask >> (i * 8)) & 0xFF;
            }
            
            for (size_t i = 0; i < GFRX_BLOCK_SIZE; i++) {
                X[i] ^= L[i];
            }
            
            gfrx_encrypt_block(&ctx.gfrx, X, Y);
            ad_blocks++;
        }
    }
    
    size_t msg_blocks = 0;
    if (ciphertext != NULL && ciphertext_len > 0) {
        size_t remaining = ciphertext_len;
        size_t offset = 0;
        
        while (remaining >= GFRX_BLOCK_SIZE) {
            byte_t X[GFRX_BLOCK_SIZE];
            byte_t M[GFRX_BLOCK_SIZE];
            rho_inverse(Y, ciphertext + offset, X, M, GFRX_BLOCK_SIZE);
            
            if (plaintext != NULL) {
                memcpy(plaintext + offset, M, GFRX_BLOCK_SIZE);
            }
            
            byte_t L[GFRX_BLOCK_SIZE];
            memset(L, 0, GFRX_BLOCK_SIZE);
            uint64_t mask = compute_mask(ctx.delta, ad_blocks + msg_blocks, 0);
            for (int i = 0; i < 8; i++) {
                L[i] = (mask >> (i * 8)) & 0xFF;
            }
            
            for (size_t i = 0; i < GFRX_BLOCK_SIZE; i++) {
                X[i] ^= L[i];
            }
            
            gfrx_encrypt_block(&ctx.gfrx, X, Y);
            
            offset += GFRX_BLOCK_SIZE;
            remaining -= GFRX_BLOCK_SIZE;
            msg_blocks++;
        }
        
        if (remaining > 0) {
            byte_t X[GFRX_BLOCK_SIZE];
            byte_t M[GFRX_BLOCK_SIZE];
            rho_inverse(Y, ciphertext + offset, X, M, remaining);
            
            if (plaintext != NULL) {
                memcpy(plaintext + offset, M, remaining);
            }
            
            byte_t L[GFRX_BLOCK_SIZE];
            memset(L, 0, GFRX_BLOCK_SIZE);
            uint64_t mask = compute_mask(ctx.delta, ad_blocks + msg_blocks, 1);
            for (int i = 0; i < 8; i++) {
                L[i] = (mask >> (i * 8)) & 0xFF;
            }
            
            for (size_t i = 0; i < GFRX_BLOCK_SIZE; i++) {
                X[i] ^= L[i];
            }
            
            gfrx_encrypt_block(&ctx.gfrx, X, Y);
            msg_blocks++;
        }
    } else {
        byte_t X[GFRX_BLOCK_SIZE];
        byte_t G_Y[GFRX_BLOCK_SIZE];
        G_function(Y, G_Y);
        memcpy(X, G_Y, GFRX_BLOCK_SIZE);
        
        byte_t L[GFRX_BLOCK_SIZE];
        memset(L, 0, GFRX_BLOCK_SIZE);
        uint64_t mask = compute_mask(ctx.delta, ad_blocks, 1);
        for (int i = 0; i < 8; i++) {
            L[i] = (mask >> (i * 8)) & 0xFF;
        }
        
        for (size_t i = 0; i < GFRX_BLOCK_SIZE; i++) {
            X[i] ^= L[i];
        }
        
        gfrx_encrypt_block(&ctx.gfrx, X, Y);
    }
    
    if (secure_compare(Y, tag, GFRX_TAG_SIZE) != 0) {
        if (plaintext != NULL) {
            secure_zero(plaintext, ciphertext_len);
        }
        secure_zero(&ctx, sizeof(cofb_ctx_t));
        return GFRX_ERR_AUTH;
    }
    
    secure_zero(&ctx, sizeof(cofb_ctx_t));
    return GFRX_SUCCESS;
}
