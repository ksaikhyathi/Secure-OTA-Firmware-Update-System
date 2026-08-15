/*
 * sha256.h - SHA-256 Cryptographic Hash Implementation
 *
 * Lightweight SHA-256 for embedded systems (no dynamic allocation).
 * Implements NIST FIPS 180-4 standard.
 *
 * Used for firmware integrity verification in OTA updates.
 * Why SHA-256 over CRC: Cryptographically secure - an attacker cannot
 * craft malicious firmware with a matching hash (collision resistant).
 */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_BLOCK_SIZE   64      /* 512 bits = 64 bytes */
#define SHA256_DIGEST_SIZE  32      /* 256 bits = 32 bytes */

typedef struct {
    uint8_t  data[SHA256_BLOCK_SIZE];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

/* Initialize SHA-256 context */
void sha256_init(SHA256_CTX *ctx);

/* Update hash with data chunk (can be called multiple times) */
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len);

/* Finalize and output 32-byte hash digest */
void sha256_final(SHA256_CTX *ctx, uint8_t *hash);

/* Convenience: compute hash in one call */
void sha256_hash(const uint8_t *data, size_t len, uint8_t *hash);

#endif /* SHA256_H */
