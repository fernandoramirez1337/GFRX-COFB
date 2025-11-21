# GFRX+COFB

Implementación de cifrado autenticado GFRX-128/128 con modo COFB.

## Características

- **GFRX-128/128**: Cifrado de bloques ligero (128-bit block, 128-bit key, 32 rounds)
- **COFB Mode**: Autenticación con datos asociados (AEAD)
- **Performance**: ~730 Mbps (GFRX), ~500 Mbps (COFB)
- **Tests**: 1,666 tests exhaustivos

## Dependencias

### Para GFRX+COFB básico
No requiere dependencias externas (C estándar solamente).

### Para benchmark comparativo (ASCON vs AES-GCM)
El programa `comparison_benchmark` requiere **OpenSSL** para AES-GCM.

**macOS (Homebrew):**
```bash
brew install openssl@3
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get install libssl-dev
```

**Linux (Fedora/RHEL):**
```bash
sudo dnf install openssl-devel
```

## Compilación

```bash
make          # Compilar librería y todos los programas
make test     # Compilar y ejecutar tests
make clean    # Limpiar artefactos
```

**Nota para macOS:** El Makefile detecta automáticamente OpenSSL instalado por Homebrew.

## Uso Básico

```c
#include "include/gfrx_cofb.h"

byte_t key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
byte_t nonce[8] = {0,1,2,3,4,5,6,7};
byte_t plaintext[] = "Hello!";
byte_t ciphertext[100], tag[16], decrypted[100];

// Cifrar
cofb_encrypt(key, nonce, NULL, 0, plaintext, 6, ciphertext, tag);

// Descifrar y verificar
if (cofb_decrypt(key, nonce, NULL, 0, ciphertext, 6, tag, decrypted) == GFRX_SUCCESS) {
    printf("OK\n");
}
```

## Estructura

```
gfrx-cofb/
├── include/gfrx_cofb.h    # API pública
├── src/
│   ├── gfrx.c             # Cifrado GFRX
│   ├── cofb.c             # Modo COFB
│   └── utils.c            # Utilidades
└── test/
    └── test_gfrx_cofb.c   # Suite de tests
```

## API

### Cifrado GFRX (Block Cipher)

```c
int gfrx_init(gfrx_ctx_t *ctx, const byte_t *key);
void gfrx_encrypt_block(const gfrx_ctx_t *ctx, const byte_t *plaintext, byte_t *ciphertext);
void gfrx_decrypt_block(const gfrx_ctx_t *ctx, const byte_t *ciphertext, byte_t *plaintext);
```

### COFB (Authenticated Encryption)

```c
int cofb_encrypt(const byte_t *key, const byte_t *nonce,
                 const byte_t *ad, size_t ad_len,
                 const byte_t *plaintext, size_t plaintext_len,
                 byte_t *ciphertext, byte_t *tag);

int cofb_decrypt(const byte_t *key, const byte_t *nonce,
                 const byte_t *ad, size_t ad_len,
                 const byte_t *ciphertext, size_t ciphertext_len,
                 const byte_t *tag, byte_t *plaintext);
```

## Tests

```bash
./bin/test_gfrx_cofb    # Ejecutar suite completa (~1,666 tests)
```

**Cobertura:**
- GFRX encrypt/decrypt (100 ciclos)
- COFB todas las longitudes (0-512 bytes)
- Autenticación y verificación de tags
- Efecto avalancha criptográfico
- Stress test (1000 operaciones)

## Herramientas

```bash
./bin/ejemplo                 # Demo interactivo
./bin/gfrx-tool encrypt       # CLI para cifrar archivos
./bin/benchmark               # Tests de performance (GFRX+COFB)
./bin/comparison_benchmark    # Comparación AEAD (GFRX+COFB vs ASCON vs AES-GCM)
```

### Benchmark Comparativo

El programa `comparison_benchmark` compara el rendimiento de tres esquemas AEAD:

- **GFRX+COFB**: Implementación propuesta en esta tesis
- **ASCON-128**: Ganador NIST LWC 2023
- **AES-128-GCM**: Estándar actual

Genera métricas de throughput (Mbps) y latencia (μs) para diferentes tamaños de mensaje.

Ver resultados completos en: [COMPARACION_RESULTADOS.md](COMPARACION_RESULTADOS.md)

## Documentación Técnica

- **[TEST_VECTORS.md](TEST_VECTORS.md)**: Vectores de prueba oficiales para validación
- **[TECHNICAL_ANALYSIS.md](TECHNICAL_ANALYSIS.md)**: Análisis técnico completo de código, performance y seguridad
- **[COMPARACION_RESULTADOS.md](COMPARACION_RESULTADOS.md)**: Comparación detallada de benchmarks

## Seguridad

- Nonce **debe** ser único por cada mensaje con la misma clave

## Performance

```
GFRX Block Cipher:  ~730 Mbps  (Apple Silicon M2)
COFB Mode (1KB):    ~500 Mbps  (Apple Silicon M2)
Efecto avalancha:   51.6%      (óptimo: ~50%)
```