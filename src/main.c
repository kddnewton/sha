#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "sha.h"

typedef enum {
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHA512_224,
    SHA512_256
} sha_algorithm;

typedef struct {
    union {
        sha1_ctx_t sha1;
        sha224_ctx_t sha224;
        sha256_ctx_t sha256;
        sha384_ctx_t sha384;
        sha512_ctx_t sha512;
        sha512_224_ctx_t sha512_224;
        sha512_256_ctx_t sha512_256;
    } as;
    sha_algorithm algorithm;
} sha_ctx_t;

static sha_algorithm
parse_algorithm(uint64_t algorithm) {
    switch (algorithm) {
        case 1: return SHA1;
        case 224: return SHA224;
        case 256: return SHA256;
        case 384: return SHA384;
        case 512: return SHA512;
        case 512224: return SHA512_224;
        case 512256: return SHA512_256;
        default: return (sha_algorithm) -1;
    }
}

static void
sha_init(sha_ctx_t *ctx, sha_algorithm algorithm) {
    ctx->algorithm = algorithm;
    switch (algorithm) {
        case SHA1: sha1_init(&ctx->as.sha1); break;
        case SHA224: sha224_init(&ctx->as.sha224); break;
        case SHA256: sha256_init(&ctx->as.sha256); break;
        case SHA384: sha384_init(&ctx->as.sha384); break;
        case SHA512: sha512_init(&ctx->as.sha512); break;
        case SHA512_224: sha512_224_init(&ctx->as.sha512_224); break;
        case SHA512_256: sha512_256_init(&ctx->as.sha512_256); break;
    }
}

static void
sha_update(sha_ctx_t *ctx, const unsigned char *message, uint64_t length) {
    switch (ctx->algorithm) {
        case SHA1: sha1_update(&ctx->as.sha1, message, length); break;
        case SHA224: sha224_update(&ctx->as.sha224, message, length); break;
        case SHA256: sha256_update(&ctx->as.sha256, message, length); break;
        case SHA384: { UINT128_DINIT(length128, 0, length); sha384_update(&ctx->as.sha384, message, length128); break; }
        case SHA512: { UINT128_DINIT(length128, 0, length); sha512_update(&ctx->as.sha512, message, length128); break; }
        case SHA512_224: { UINT128_DINIT(length128, 0, length); sha512_224_update(&ctx->as.sha512_224, message, length128); break; }
        case SHA512_256: { UINT128_DINIT(length128, 0, length); sha512_256_update(&ctx->as.sha512_256, message, length128); break; }
    }
}

static void
sha_print(uint8_t *digest, uint32_t bytes) {
    uint32_t index;
    for (index = 0; index < bytes; ++index) printf("%02x", digest[index]);
    printf("\n");
}

static void
sha_final(sha_ctx_t *ctx) {
    switch (ctx->algorithm) {
        case SHA1: { uint8_t digest[20]; sha1_final(&ctx->as.sha1, digest); sha_print(digest, sizeof(digest)); break; }
        case SHA224: { uint8_t digest[28]; sha224_final(&ctx->as.sha224, digest); sha_print(digest, sizeof(digest)); break; }
        case SHA256: { uint8_t digest[32]; sha256_final(&ctx->as.sha256, digest); sha_print(digest, sizeof(digest)); break; }
        case SHA384: { uint8_t digest[48]; sha384_final(&ctx->as.sha384, digest); sha_print(digest, sizeof(digest)); break; }
        case SHA512: { uint8_t digest[64]; sha512_final(&ctx->as.sha512, digest); sha_print(digest, sizeof(digest)); break; }
        case SHA512_224: { uint8_t digest[28]; sha512_224_final(&ctx->as.sha512_224, digest); sha_print(digest, sizeof(digest)); break; }
        case SHA512_256: { uint8_t digest[32]; sha512_256_final(&ctx->as.sha512_256, digest); sha_print(digest, sizeof(digest)); break; }
    }
}

int
main(int argc, char *argv[]) {
    uint64_t arg1, arg2;

    sha_algorithm algorithm;
    sha_ctx_t ctx;
    uint64_t bit_length, index;

    unsigned char buffer[1024];

    if (argc != 3 || sscanf(argv[1], "%" SCNu64, &arg1) != 1 || sscanf(argv[2], "%" SCNu64, &arg2) != 1) {
        fprintf(stderr, "Usage: %s <algorithm> <bit-length>\n", argv[0]);
        return EXIT_FAILURE;
    }

    algorithm = parse_algorithm(arg1);
    if (algorithm == (sha_algorithm) -1) {
        fprintf(stderr, "Unsupported algorithm: %" PRIu64 "\n", arg1);
        return EXIT_FAILURE;
    }
    
    sha_init(&ctx, algorithm);
    bit_length = arg2;

    for (index = 0; index < bit_length; index += CHAR_BIT * 1024) {
        uint64_t chunk_bits = (bit_length - index < CHAR_BIT * 1024 ? bit_length - index : CHAR_BIT * 1024);
        uint64_t chunk_read = fread(buffer, (chunk_bits + CHAR_BIT - 1) / CHAR_BIT, 1, stdin);

        if (chunk_read != 1) {
            fprintf(stderr, "Error reading from stdin\n");
            return EXIT_FAILURE;
        }

        sha_update(&ctx, buffer, chunk_bits);
    }

    sha_final(&ctx);
    return EXIT_SUCCESS;
}
