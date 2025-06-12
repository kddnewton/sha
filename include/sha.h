/* Implementations of the secure hashing algorithm standard functions.
 *
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 */

#ifndef SHA_H
#define SHA_H

#include <limits.h>
#include <stdint.h>

/* SHA-512 algorithms use 128-bit message lengths, so we need a uint128_t type
 * to represent that size. We also define UINT128* macros to create uint128_t
 * instances from two component 64-bit integers.
 */
#ifdef __SIZEOF_INT128__
typedef __uint128_t uint128_t;
#define UINT128_DECL(name_) uint128_t name_
#define UINT128_INIT(name_, hi_, lo_) name_ = ((uint128_t) (hi_) << 64 | (lo_))
#define UINT128_DINIT(name_, hi_, lo_) uint128_t name_ = ((uint128_t) (hi_) << 64 | (lo_))
#else
typedef struct { uint64_t hi; uint64_t lo; } uint128_t;
#define UINT128_DECL(name_) uint128_t name_
#define UINT128_INIT(name_, hi_, lo_) name_.hi = (hi_); name_.lo = (lo_)
#define UINT128_DINIT(name_, hi_, lo_) UINT128_DECL(name_); UINT128_INIT(name_, hi_, lo_)
#endif

typedef struct {
    uint64_t length;
    uint32_t state[5];
    uint32_t working[5];
    unsigned char buffer[(512 + (CHAR_BIT - 1)) / CHAR_BIT];
} sha1_ctx_t;

typedef struct {
    uint64_t length;
    uint32_t state[8];
    uint32_t working[8];
    unsigned char buffer[(512 + (CHAR_BIT - 1)) / CHAR_BIT];
} sha256_base_ctx_t;

typedef struct {
    sha256_base_ctx_t base;
} sha224_ctx_t;

typedef struct {
    sha256_base_ctx_t base;
} sha256_ctx_t;

typedef struct {
    uint128_t length;
    uint64_t state[8];
    uint64_t working[8];
    unsigned char buffer[(1024 + (CHAR_BIT - 1)) / CHAR_BIT];
} sha512_base_ctx_t;

typedef struct {
    sha512_base_ctx_t base;
} sha384_ctx_t;

typedef struct {
    sha512_base_ctx_t base;
} sha512_ctx_t;

typedef struct {
    sha512_base_ctx_t base;
} sha512_224_ctx_t;

typedef struct {
    sha512_base_ctx_t base;
} sha512_256_ctx_t;

/* Initialize the SHA-1 context.
 *
 * @param ctx The SHA-1 context to initialize.
 */
void sha1_init(sha1_ctx_t *ctx);

/* Update the SHA-1 context with a message.
 *
 * @param ctx The SHA-1 context to update.
 * @param message A pointer to the message to be hashed.
 * @param length The size of the message pointer in bits.
 */
void sha1_update(sha1_ctx_t *ctx, const unsigned char *message, uint64_t length);

/* Finalize the SHA-1 context and produce the digest.
 *
 * @param ctx The SHA-1 context to finalize.
 * @param digest The 20-byte output buffer for the digest.
 */
void sha1_final(sha1_ctx_t *ctx, uint8_t digest[20]);

/* Initialize the SHA-224 context.
 *
 * @param ctx The SHA-224 context to initialize.
 */
void sha224_init(sha224_ctx_t *ctx);

/* Update the SHA-224 context with a message.
 *
 * @param ctx The SHA-224 context to update.
 * @param message A pointer to the message to be hashed.
 * @param length The size of the message pointer in bits.
 */
void sha224_update(sha224_ctx_t *ctx, const unsigned char *message, uint64_t length);

/* Finalize the SHA-224 context and produce the digest.
 *
 * @param ctx The SHA-224 context to finalize.
 * @param digest The 28-byte output buffer for the digest.
 */
void sha224_final(sha224_ctx_t *ctx, uint8_t digest[28]);

/* Initialize the SHA-256 context.
 *
 * @param ctx The SHA-256 context to initialize.
 */
void sha256_init(sha256_ctx_t *ctx);

/* Update the SHA-256 context with a message.
 *
 * @param ctx The SHA-256 context to update.
 * @param message A pointer to the message to be hashed.
 * @param length The size of the message pointer in bits.
 */
void sha256_update(sha256_ctx_t *ctx, const unsigned char *message, uint64_t length);

/* Finalize the SHA-256 context and produce the digest.
 *
 * @param ctx The SHA-256 context to finalize.
 * @param digest The 32-byte output buffer for the digest.
 */
void sha256_final(sha256_ctx_t *ctx, uint8_t digest[32]);

/* Initialize the SHA-384 context.
 *
 * @param ctx The SHA-384 context to initialize.
 */
void sha384_init(sha384_ctx_t *ctx);

/* Update the SHA-384 context with a message.
 *
 * @param ctx The SHA-384 context to update.
 * @param message A pointer to the message to be hashed.
 * @param length The size of the message pointer in bits.
 */
void sha384_update(sha384_ctx_t *ctx, const unsigned char *message, uint128_t length);

/* Finalize the SHA-384 context and produce the digest.
 *
 * @param ctx The SHA-384 context to finalize.
 * @param digest The 48-byte output buffer for the digest.
 */
void sha384_final(sha384_ctx_t *ctx, uint8_t digest[48]);

/* Initialize the SHA-512 context.
 *
 * @param ctx The SHA-512 context to initialize.
 */
void sha512_init(sha512_ctx_t *ctx);

/* Update the SHA-512 context with a message.
 *
 * @param ctx The SHA-512 context to update.
 * @param message A pointer to the message to be hashed.
 * @param message_length The size of the message pointer in bits.
 */
void sha512_update(sha512_ctx_t *ctx, const unsigned char *message, uint128_t length);

/* Finalize the SHA-512 context and produce the digest.
 *
 * @param ctx The SHA-512 context to finalize.
 * @param digest The 64-byte output buffer for the digest.
 */
void sha512_final(sha512_ctx_t *ctx, uint8_t digest[64]);

/* Initialize the SHA-512/224 context.
 *
 * @param ctx The SHA-512/224 context to initialize.
 */
void sha512_224_init(sha512_224_ctx_t *ctx);

/* Update the SHA-512/224 context with a message.
 *
 * @param ctx The SHA-512/224 context to update.
 * @param message A pointer to the message to be hashed.
 * @param message_length The size of the message pointer in bits.
 */
void sha512_224_update(sha512_224_ctx_t *ctx, const unsigned char *message, uint128_t length);

/* Finalize the SHA-512/224 context and produce the digest.
 *
 * @param ctx The SHA-512/224 context to finalize.
 * @param digest The 28-byte output buffer for the digest.
 */
void sha512_224_final(sha512_224_ctx_t *ctx, uint8_t digest[28]);

/* Initialize the SHA-512/256 context.
 *
 * @param ctx The SHA-512/256 context to initialize.
 */
void sha512_256_init(sha512_256_ctx_t *ctx);

/* Update the SHA-512/256 context with a message.
 *
 * @param ctx The SHA-512/256 context to update.
 * @param message A pointer to the message to be hashed.
 * @param message_length The size of the message pointer in bits.
 */
void sha512_256_update(sha512_256_ctx_t *ctx, const unsigned char *message, uint128_t length);

/* Finalize the SHA-512/256 context and produce the digest.
 *
 * @param ctx The SHA-512/256 context to finalize.
 * @param digest The 32-byte output buffer for the digest.
 */
void sha512_256_final(sha512_256_ctx_t *ctx, uint8_t digest[32]);

#endif
