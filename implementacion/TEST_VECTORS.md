# GFRX+COFB Test Vectors

**Purpose:** Official test vectors for GFRX+COFB authenticated encryption validation and reproducibility.

**Date:** 2025-11-18
**Implementation:** First GFRX+COFB reference implementation
**Format:** Hexadecimal (lowercase, no separators)

---

## Overview

These test vectors enable:

- Implementation validation and correctness verification
- Regression testing during development
- Interoperability between implementations
- Academic reproducibility

All vectors generated with the reference implementation using GCC `-O2 -std=c99` on Linux x86-64.

---

## Format Specification

### Parameters

| Symbol | Description | Size (bits) | Size (bytes) |
|--------|-------------|-------------|--------------|
| K | Key | 128 | 16 |
| N | Nonce | 64 | 8 |
| AD | Associated Data | Variable | Variable |
| M | Message/Plaintext | Variable | Variable |
| C | Ciphertext | Variable | Variable |
| T | Authentication Tag | 128 | 16 |

### AEAD Interface

**Encryption:**
```
(C, T) = GFRX_COFB_Encrypt(K, N, AD, M)
```

**Decryption:**
```
M = GFRX_COFB_Decrypt(K, N, AD, C, T)
Returns: M (plaintext) or ⊥ (authentication failure)
```

---

## Test Vectors

### Test Vector 1: GFRX-128 Block Cipher

Key       : 000102030405060708090a0b0c0d0e0f
Plaintext : 00112233445566778899aabbccddeeff
Ciphertext: c41ba148c47e5ee84e518b73772ffb61
Decrypted : 00112233445566778899aabbccddeeff

### Test Vector 2: COFB Empty Message

Key   : 000102030405060708090a0b0c0d0e0f
Nonce : 1011121314151617
AD Length    : 0
Message Length: 0
Tag   : e91df11ffbd6732751bae51c68c07106

### Test Vector 3: COFB with 8-byte Message

Key       : 000102030405060708090a0b0c0d0e0f
Nonce     : 2021222324252627
AD Length    : 0
Message Length: 8
Plaintext : 0001020304050607
Ciphertext: b2d89618c78f624c
Tag       : 3a588edba1abb0c0ac6edf4488811923

### Test Vector 4: COFB with 16-byte Message (One Block)

Key       : 000102030405060708090a0b0c0d0e0f
Nonce     : 3031323334353637
AD Length    : 0
Message Length: 16
Plaintext : 000102030405060708090a0b0c0d0e0f
Ciphertext: 428cc23cabf2d43307afc3e103a9446e
Tag       : da97a83b50c4e747963b5bd36f8717ee

### Test Vector 5: COFB with 64-byte Message (Four Blocks)

Key       : 000102030405060708090a0b0c0d0e0f
Nonce     : 4041424344454647
AD Length    : 0
Message Length: 64
Plaintext : 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
Ciphertext: 00972ae5ff6ca54f834e18227b5682c4847dc8e8940ca8180306c80ccff1ca39b4858cd535efad7949dc8312657bae60d3734ea5013db78e797a6c846f854c85
Tag       : 9b7a2f0356be6289e7c324a6b650b3af

### Test Vector 6: COFB with Associated Data

Key       : 000102030405060708090a0b0c0d0e0f
Nonce     : 5051525354555657
AD Length    : 16
AD        : aaabacadaeafb0b1b2b3b4b5b6b7b8b9
Message Length: 32
Plaintext : 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Ciphertext: bc8fcc13c1413a947543dafed6e18c96d216163bd1bd453db90d6e2fa1ff23b8
Tag       : 52af6182b5d968bbc3e5738c3e344639

### Test Vector 7: COFB with Text Message

Key       : 000102030405060708090a0b0c0d0e0f
Nonce     : 6061626364656667
AD Length    : 0
Message Length: 17
Plaintext : "Hello, GFRX+COFB!"
Ciphertext: 5c9e809ae293dccd9b1cc0b3012abfc399
Tag       : 497c0318c5615cb7eb5cdaba3ff60923

### Test Vector 8: All-Zero Key and Nonce

Key       : 00000000000000000000000000000000
Nonce     : 0000000000000000
AD Length    : 0
Message Length: 16
Plaintext : 00000000000000000000000000000000
Ciphertext: 0de20506f8b2045f7c51f8a0fa1bacc1
Tag       : 7857874a35d87c9ef6bdb8df3c0dc954

### Test Vector 9: All-FF Key and Message

Key       : ffffffffffffffffffffffffffffffff
Nonce     : ffffffffffffffff
AD Length    : 0
Message Length: 16
Plaintext : ffffffffffffffffffffffffffffffff
Ciphertext: 1cf048ff516367e2121f2a51a75438bd
Tag       : 205aadaf80e3413bc124ab3bed9661df

### Test Vector 10: Long Message (256 bytes)

Key       : 000102030405060708090a0b0c0d0e0f
Nonce     : 7071727374757677
AD Length    : 0
Message Length: 256
Plaintext : 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
Ciphertext: 7804cef1e3831d7d7a1afd66f88c3f32ab5203d1a086973549bff4873e8764cff2970b470895122c05de94a193431acf0167be961fb7ab1795cb50717fcedf0d43ca57e2171511f6593f6024e67eed64aeaf30350668534db1353fbabeeeb0ba9f11d2312907e880e1770f98ca4acc24ce3a69a60e12dce16265f0f5f6b6a9fd8eb770ee0e738372a350574b767503a2fbff48eda09ca2bfa6844ba888fc79b9849f4dbe3af29975d4d058375cf95d2c52205599120024dc8f8c4517a1e10888cfd89e38dfb6981edc534c7dccb41087f3bf8a213d4d470b0d214bdb0b113314487be0a46eb40905764d56be837059ec4ffe24db6111a218674a47a7ff3f307d
Tag       : c19d1024fd5692fd12bb44ef206f62fe

---

## Validation Procedure

### Using the Reference Implementation

```bash
cd implementacion

# Generate fresh test vectors
./bin/generate_test_vectors > my_vectors.txt

# Compare with official vectors
diff my_vectors.txt TEST_VECTORS.md
# Should show no differences in hex values
```

### Manual Verification (Example)

```c
#include "include/gfrx_cofb.h"

byte_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                  0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
byte_t nonce[8] = {0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17};
byte_t plaintext[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
byte_t ciphertext[16], tag[16];

// Encrypt
cofb_encrypt(key, nonce, NULL, 0, plaintext, 16, ciphertext, tag);

// Expected ciphertext: c41ba148c47e5ee84e518b73772ffb61
// Expected tag: e91df11ffbd6732751bae51c68c07106
```

---

## Notes

- **Nonce uniqueness:** Never reuse a nonce with the same key
- **Tag verification:** Always verify the tag before using decrypted data
- **Security level:** 128-bit security for both confidentiality and authenticity
- **Birthday bound:** Secure up to 2^64 blocks per key

---

**Generated:** 2025-11-18
**Compiler:** GCC -O2 -std=c99
**Platform:** Linux x86-64
