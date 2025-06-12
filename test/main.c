#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha.h"

#define LINE_MAXIMUM 0x20000

static int
scan_byte(const char *src, char *dst) {
    unsigned int value;

#ifdef _WIN32
    if (sscanf_s(src, "%2x", &value) != 1) return -1;
#else
    if (sscanf(src, "%2x", &value) != 1) return -1;
#endif

    if (value > UCHAR_MAX) {
        fprintf(stderr, "Invalid byte value: %s\n", src);
        return -1;
    }

    *dst = (char) value;
    return 1;
}

static int
scan_length(const char *src, uint64_t *dst) {
#ifdef _WIN32
    return sscanf_s(src, "%" SCNu64, dst);
#else
    return sscanf(src, "%" SCNu64, dst);
#endif
}

static int
print_byte(char *dst, uint8_t byte) {
#ifdef _WIN32
    return sprintf_s(dst, 3, "%02x", byte);
#else
    return sprintf(dst, "%02x", byte);
#endif
}

typedef enum {
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHA512_224,
    SHA512_256
} sha_algorithm;

typedef union {
    sha1_ctx_t sha1;
    sha224_ctx_t sha224;
    sha256_ctx_t sha256;
    sha384_ctx_t sha384;
    sha512_ctx_t sha512;
    sha512_224_ctx_t sha512_224;
    sha512_256_ctx_t sha512_256;
} sha_ctx_t;

static uint8_t
sha_algorithm_length(sha_algorithm algorithm) {
    switch (algorithm) {
        case SHA1: return 20;
        case SHA224: return 28;
        case SHA256: return 32;
        case SHA384: return 48;
        case SHA512: return 64;
        case SHA512_224: return 28;
        case SHA512_256: return 32;
    }
    return 0;
}

static void
sha_init(sha_ctx_t *ctx, sha_algorithm algorithm) {
    switch (algorithm) {
        case SHA1: sha1_init(&ctx->sha1); break;
        case SHA224: sha224_init(&ctx->sha224); break;
        case SHA256: sha256_init(&ctx->sha256); break;
        case SHA384: sha384_init(&ctx->sha384); break;
        case SHA512: sha512_init(&ctx->sha512); break;
        case SHA512_224: sha512_224_init(&ctx->sha512_224); break;
        case SHA512_256: sha512_256_init(&ctx->sha512_256); break;
    }
}

static void
sha_update(sha_ctx_t *ctx, sha_algorithm algorithm, const unsigned char *message, uint64_t length) {
    switch (algorithm) {
        case SHA1: sha1_update(&ctx->sha1, message, length); break;
        case SHA224: sha224_update(&ctx->sha224, message, length); break;
        case SHA256: sha256_update(&ctx->sha256, message, length); break;
        case SHA384: { UINT128_DINIT(length128, 0, length); sha384_update(&ctx->sha384, message, length128); break; }
        case SHA512: { UINT128_DINIT(length128, 0, length); sha512_update(&ctx->sha512, message, length128); break; }
        case SHA512_224: { UINT128_DINIT(length128, 0, length); sha512_224_update(&ctx->sha512_224, message, length128); break; }
        case SHA512_256: { UINT128_DINIT(length128, 0, length); sha512_256_update(&ctx->sha512_256, message, length128); break; }
    }
}

static void
sha_print(unsigned char *dst, const uint8_t *digest, uint32_t bytes) {
    uint32_t index;
    for (index = 0; index < bytes; ++index) {
        print_byte((char *) dst + index * 2, digest[index]);
    }
}

static void
sha_final(sha_ctx_t *ctx, sha_algorithm algorithm, unsigned char *dst) {
    switch (algorithm) {
        case SHA1: { uint8_t digest[20]; sha1_final(&ctx->sha1, digest); sha_print(dst, digest, sizeof(digest)); break; }
        case SHA224: { uint8_t digest[28]; sha224_final(&ctx->sha224, digest); sha_print(dst, digest, sizeof(digest)); break; }
        case SHA256: { uint8_t digest[32]; sha256_final(&ctx->sha256, digest); sha_print(dst, digest, sizeof(digest)); break; }
        case SHA384: { uint8_t digest[48]; sha384_final(&ctx->sha384, digest); sha_print(dst, digest, sizeof(digest)); break; }
        case SHA512: { uint8_t digest[64]; sha512_final(&ctx->sha512, digest); sha_print(dst, digest, sizeof(digest)); break; }
        case SHA512_224: { uint8_t digest[28]; sha512_224_final(&ctx->sha512_224, digest); sha_print(dst, digest, sizeof(digest)); break; }
        case SHA512_256: { uint8_t digest[32]; sha512_256_final(&ctx->sha512_256, digest); sha_print(dst, digest, sizeof(digest)); break; }
    }
}

static int
run_tests(sha_algorithm algorithm, const char *filepath) {
    sha_ctx_t ctx;
    uint64_t bit_length = (uint64_t) -1;

    char line[LINE_MAXIMUM];
    unsigned char buffer[1025];
    unsigned char actual[129];
    int result = 0;

    FILE *file;
    fprintf(stderr, "Running %s\n", filepath);

    file = fopen(filepath, "r");
    if (!file) return -1;

    while (fgets(line, LINE_MAXIMUM, file)) {
        if (memcmp(line, "Len = ", 6) == 0) {
            if (scan_length(line + 6, &bit_length) != 1) {
                fprintf(stderr, "Invalid length format: %s\n", line);
                fclose(file);
                return -1;
            }
        } else if (memcmp(line, "Msg = ", 6) == 0) {
            uint64_t chunk_index;
            sha_init(&ctx, algorithm);

            for (chunk_index = 0; chunk_index < bit_length; chunk_index += CHAR_BIT * 1024) {
                uint64_t chunk_size = (bit_length - chunk_index < CHAR_BIT * 1024 ? bit_length - chunk_index : CHAR_BIT * 1024);
                uint64_t index;

                for (index = 0; index < chunk_size; index += CHAR_BIT) {
                    if (scan_byte(line + 6 + ((index + chunk_index) / CHAR_BIT) * 2, (char *) buffer + (index / CHAR_BIT)) != 1) {
                        fprintf(stderr, "Invalid input format: %s\n", line);
                        fclose(file);
                        return -1;
                    }
                }

                sha_update(&ctx, algorithm, buffer, chunk_size);
            }
        } else if (memcmp(line, "MD = ", 5) == 0) {
            size_t length = sha_algorithm_length(algorithm) * 2;
            sha_final(&ctx, algorithm, actual);

            if (memcmp(line + 5, actual, length) != 0) {
                result = 1;
                fprintf(
                    stderr,
                    "%s\n"
                    "    Len: %" PRIu64 "\n"
                    "    Expected: %.*s\n"
                    "    Actual: %.*s\n",
                    filepath,
                    bit_length,
                    (int) length, line + 5,
                    (int) length, actual
                );
            }
        }
    }

    if (fclose(file)) return -1;
    return result;
}

int
main(int argc, char *argv[]) {
    int result = EXIT_SUCCESS;
    char filepath[1024];
    const char *directory;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <directory>\n", argv[0]);
        return EXIT_FAILURE;
    }

    directory = argv[1];

#define CHECK(algorithm_, filename_) \
    do { \
        snprintf(filepath, sizeof(filepath), "%s/%s", directory, filename_); \
        if (run_tests(algorithm_, filepath)) result = EXIT_FAILURE; \
    } while (0)

    CHECK(SHA1, "shabittestvectors/SHA1ShortMsg.rsp");
    CHECK(SHA1, "shabittestvectors/SHA1LongMsg.rsp");
    CHECK(SHA1, "shabytetestvectors/SHA1ShortMsg.rsp");
    CHECK(SHA1, "shabytetestvectors/SHA1LongMsg.rsp");

    CHECK(SHA224, "shabittestvectors/SHA224ShortMsg.rsp");
    CHECK(SHA224, "shabittestvectors/SHA224LongMsg.rsp");
    CHECK(SHA224, "shabytetestvectors/SHA224ShortMsg.rsp");
    CHECK(SHA224, "shabytetestvectors/SHA224LongMsg.rsp");

    CHECK(SHA256, "shabittestvectors/SHA256ShortMsg.rsp");
    CHECK(SHA256, "shabittestvectors/SHA256LongMsg.rsp");
    CHECK(SHA256, "shabytetestvectors/SHA256ShortMsg.rsp");
    CHECK(SHA256, "shabytetestvectors/SHA256LongMsg.rsp");

    CHECK(SHA384, "shabittestvectors/SHA384ShortMsg.rsp");
    CHECK(SHA384, "shabittestvectors/SHA384LongMsg.rsp");
    CHECK(SHA384, "shabytetestvectors/SHA384ShortMsg.rsp");
    CHECK(SHA384, "shabytetestvectors/SHA384LongMsg.rsp");

    CHECK(SHA512, "shabittestvectors/SHA512ShortMsg.rsp");
    CHECK(SHA512, "shabittestvectors/SHA512LongMsg.rsp");
    CHECK(SHA512, "shabytetestvectors/SHA512ShortMsg.rsp");
    CHECK(SHA512, "shabytetestvectors/SHA512LongMsg.rsp");

    CHECK(SHA512_224, "shabittestvectors/SHA512_224ShortMsg.rsp");
    CHECK(SHA512_224, "shabittestvectors/SHA512_224LongMsg.rsp");
    CHECK(SHA512_224, "shabytetestvectors/SHA512_224ShortMsg.rsp");
    CHECK(SHA512_224, "shabytetestvectors/SHA512_224LongMsg.rsp");

    CHECK(SHA512_256, "shabittestvectors/SHA512_256ShortMsg.rsp");
    CHECK(SHA512_256, "shabittestvectors/SHA512_256LongMsg.rsp");
    CHECK(SHA512_256, "shabytetestvectors/SHA512_256ShortMsg.rsp");
    CHECK(SHA512_256, "shabytetestvectors/SHA512_256LongMsg.rsp");

#undef CHECK

    return result;
}
