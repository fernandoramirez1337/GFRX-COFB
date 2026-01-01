# GFRX+COFB

**Lightweight Authenticated Encryption with Associated Data for IoT Environments**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C99](https://img.shields.io/badge/C-99-blue.svg)](https://en.wikipedia.org/wiki/C99)

## Overview

GFRX+COFB is a lightweight authenticated encryption scheme designed for resource-constrained IoT devices. It combines:

- **GFRX-128/128**: A lightweight block cipher based on a generalized Feistel structure with ARX (Add-Rotate-XOR) operations
- **COFB Mode**: Combined Feedback mode for Authenticated Encryption with Associated Data (AEAD)

The scheme achieves only **320 bits of total state**, making it ideal for devices with limited memory and processing power.

### Key Features

- 🔐 **128-bit security level** with 128-bit key and 128-bit block size
- ⚡ **Efficient on small messages**: 1.5x faster than ASCON-128 for 16-64 byte messages
- 💾 **Minimal state**: Only 320 bits (40 bytes) of internal state
- 🧪 **Extensively tested**: 1,666+ test vectors including avalanche effect analysis
- 🔧 **No dependencies**: Pure C99 implementation (except optional benchmark comparisons)

## Repository Structure

```
GFRX-COFB/
├── README.md                 # This file
├── implementacion/           # C implementation of GFRX+COFB
│   ├── include/              # Header files
│   │   └── gfrx_cofb.h       # Public API
│   ├── src/                  # Source files
│   │   ├── gfrx.c            # GFRX block cipher
│   │   ├── cofb.c            # COFB AEAD mode
│   │   └── utils.c           # Utility functions
│   ├── test/                 # Test suite
│   ├── Makefile              # Build system
│   ├── README.md             # Implementation details
│   ├── TECHNICAL_ANALYSIS.md # Technical analysis
│   ├── TEST_VECTORS.md       # Test vectors
│   └── COMPARACION_RESULTADOS.md  # Benchmark comparison results
│
└── redaccion/                # Thesis documentation (LaTeX)
    ├── Tesis.tex             # Main thesis document
    ├── Cap_1.tex - Cap_4.tex # Thesis chapters
    └── figs/                 # Figures and diagrams
```

## Quick Start

### Prerequisites

- C compiler (GCC, Clang, or compatible)
- Make build system

### Build

```bash
cd implementacion
make            # Build library and all executables
make test       # Build and run test suite
```

### Basic Usage

```c
#include "include/gfrx_cofb.h"

byte_t key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
byte_t nonce[8] = {0,1,2,3,4,5,6,7};
byte_t plaintext[] = "Hello, IoT!";
byte_t ciphertext[100], tag[16], decrypted[100];

// Encrypt with authentication
cofb_encrypt(key, nonce, NULL, 0, plaintext, 11, ciphertext, tag);

// Decrypt and verify
if (cofb_decrypt(key, nonce, NULL, 0, ciphertext, 11, tag, decrypted) == GFRX_SUCCESS) {
    printf("Decryption successful!\n");
}
```

## Performance

Benchmark results on x86-64 CPU:

| Message Size | GFRX+COFB | ASCON-128 | Notes |
|--------------|-----------|-----------|-------|
| 16 bytes     | 289 Mbps  | 191 Mbps  | GFRX+COFB 1.51x faster |
| 64 bytes     | 617 Mbps  | 394 Mbps  | GFRX+COFB 1.56x faster |
| 256 bytes    | 889 Mbps  | 533 Mbps  | GFRX+COFB 1.67x faster |
| 1024 bytes   | 871 Mbps  | 595 Mbps  | GFRX+COFB 1.47x faster |

**Optimal for IoT**: GFRX+COFB excels at small message sizes (16-1024 bytes), which are typical in IoT sensor communications.

## Tools

The implementation includes several command-line tools:

```bash
./bin/test_gfrx_cofb        # Run full test suite (1,666 tests)
./bin/ejemplo               # Interactive demo
./bin/gfrx-tool             # CLI for file encryption
./bin/benchmark             # Performance benchmarks
./bin/comparison_benchmark  # AEAD comparison (GFRX+COFB vs ASCON vs AES-GCM)
```

## Documentation

- **Implementation README**: [implementacion/README.md](implementacion/README.md) - Detailed API documentation, build instructions, and usage examples
- **Technical Analysis**: [implementacion/TECHNICAL_ANALYSIS.md](implementacion/TECHNICAL_ANALYSIS.md) - Complete technical analysis of the implementation
- **Test Vectors**: [implementacion/TEST_VECTORS.md](implementacion/TEST_VECTORS.md) - Official test vectors for validation
- **Benchmark Comparison**: [implementacion/COMPARACION_RESULTADOS.md](implementacion/COMPARACION_RESULTADOS.md) - Detailed performance comparison with ASCON and AES-GCM

## Thesis

This project is part of a thesis on authenticated encryption for IoT environments at Universidad Católica San Pablo (UCSP), Arequipa, Peru.

**Title**: *Implementación de Cifrado Autenticado con Datos Asociados GFRX+COFB para entornos IoT*

**Author**: Fernando Ramirez Arredondo

**Advisor**: Dr. Yván Jesús Túpac Valdivia

The thesis documentation is available in the `redaccion/` directory (in Spanish).

## Security Considerations

- **Nonce uniqueness**: The nonce MUST be unique for each message encrypted with the same key
- **Tag verification**: Always verify the authentication tag before using decrypted data
- **Key management**: Store and handle keys securely according to best practices

## License

This project is open source. See the implementation for specific licensing details.

## References

- GFRX: Generalized Feistel cipher with ARX operations
- COFB: Combined Feedback mode for AEAD (NIST LWC candidate)
- ASCON: NIST Lightweight Cryptography winner (2023)
