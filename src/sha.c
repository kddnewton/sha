#include <assert.h>
#include <limits.h>
#include <stdint.h>

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#include <stdalign.h>
#elif defined(_MSC_VER)
#define alignas(x) __declspec(align(x))
#elif defined(__GNUC__) || defined(__clang__)
#define alignas(x) __attribute__((aligned(x)))
#else
#define alignas(x)
#endif

#if defined(__STDC_NO_VLA__) || (defined(_MSC_VER) && !defined(__clang__)) || !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L)
#include <stdlib.h>
#define VLA_DECL(type_, name_, size_) type_ *name_
#define VLA_INIT(type_, name_, size_) name_ = (type_ *) malloc(size_)
#define VLA_DINIT(type_, name_, size_) type_ *name_ = (type_ *) malloc(size_)
#define VLA_FREE(name_) free(name_)
#else
#define VLA_DECL(type_, name_, size_) type_ name_[size_]
#define VLA_INIT(type_, name_, size_)
#define VLA_DINIT VLA_DECL
#define VLA_FREE(name_)
#endif

#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#include <string.h>

#if defined(__STDC_LIB_EXT1__)
#define memzero(p, s) memset_s((p), (s), 0, (s))
#elif defined(__APPLE__)
#define memzero(p, s) memset_s((p), (s), 0, (s))
#elif defined(_WIN32)
#include <windows.h>
#define memzero(p, s) (SecureZeroMemory(p, s), 0)
#else
static int
memzero(void *p, size_t s) {
    volatile char *c = (volatile char *) p;
    while (s--) *c++ = 0;
    return 0;
}
#endif

#include "sha.h"

#ifdef __SIZEOF_INT128__
static const uint128_t UINT128_0 = (uint128_t) 0;
static const uint128_t UINT128_1024 = (uint128_t) 1024;
static const uint128_t UINT128_CHARBIT = (uint128_t) CHAR_BIT;

static uint64_t
uint128_u64(const uint128_t a) {
    assert(a >> 64 == 0);
    return (uint64_t) a;
}

#define uint128_lt(a, b) ((a) < (b))
#define uint128_gt(a, b) ((a) > (b))

#define uint128_add(a, b) ((a) + (b))
#define uint128_sub(a, b) ((a) - (b))

#define uint128_and(a, b) ((a) & (b))
#define uint128_shr(a, shift) ((a) >> (shift))

#define uint128_div(dividend, divisor) ((dividend) / (divisor))
#define uint128_mod(dividend, divisor) ((dividend) % (divisor))

#define uint128_bool(a) (a)
#else
static const uint128_t UINT128_0 = { 0, 0 };
static const uint128_t UINT128_1024 = { 0, 1024 };
static const uint128_t UINT128_CHARBIT = { 0, CHAR_BIT };

static uint64_t
uint128_u64(const uint128_t a) {
    assert(a.hi == 0);
    return a.lo;
}

static int
uint128_lt(const uint128_t a, const uint128_t b) {
    if (a.hi < b.hi) return 1;
    if (a.hi > b.hi) return 0;
    return a.lo < b.lo;
}

static int
uint128_gt(uint128_t a, uint128_t b) {
    if (a.hi > b.hi) return 1;
    if (a.hi < b.hi) return 0;
    return a.lo > b.lo;
}

static int
uint128_ge(const uint128_t a, const uint128_t b) {
    if (a.hi > b.hi) return 1;
    if (a.hi < b.hi) return 0;
    return a.lo >= b.lo;
}

static uint128_t
uint128_add(const uint128_t a, const uint128_t b) {
    uint128_t result;
    result.lo = a.lo + b.lo;
    result.hi = a.hi + b.hi + (result.lo < a.lo ? 1 : 0);
    return result;
}

static uint128_t
uint128_sub(const uint128_t a, const uint128_t b) {
    uint128_t result;
    result.lo = a.lo - b.lo;
    result.hi = a.hi - b.hi - (a.lo < b.lo ? 1 : 0);
    return result;
}

static uint128_t
uint128_and(const uint128_t a, const uint128_t b) {
    uint128_t result;
    result.lo = a.lo & b.lo;
    result.hi = a.hi & b.hi;
    return result;
}

static uint128_t
uint128_shl(const uint128_t a, unsigned shift) {
    uint128_t result = UINT128_0;
    if (shift == 0) return a;

    if (shift < 64) {
        result.hi = (a.hi << shift) | (a.lo >> (64 - shift));
        result.lo = a.lo << shift;
    } else {
        result.hi = a.lo << (shift - 64);
    }

    return result;
}

static uint128_t
uint128_shr(const uint128_t a, unsigned shift) {
    uint128_t result = UINT128_0;
    if (shift == 0) return a;

    if (shift < 64) {
        result.lo = (a.lo >> shift) | (a.hi << (64 - shift));
        result.hi = a.hi >> shift;
    } else {
        result.lo = a.hi >> (shift - 64);
    }

    return result;
}

static uint128_t
uint128_div_internal(uint128_t dividend, uint128_t divisor, uint128_t *remain) {
    uint128_t quotient = UINT128_0;
    uint128_t remainder = dividend;
    uint128_t current = divisor;

    unsigned shift = 0;
    uint128_t shifted;

    if (divisor.hi == 0 && divisor.lo == 0) return UINT128_0;

    while (shifted = uint128_shl(current, 1), uint128_ge(remainder, shifted)) {
        current = shifted;
        shift++;
    }

    while (1) {
        if (uint128_ge(remainder, current)) {
            remainder = uint128_sub(remainder, current);
            if (shift >= 64) {
                uint64_t shift64 = 1;
                shift64 <<= (shift - 64);
                quotient.hi |= shift64;
            } else {
                uint64_t shift64 = 1;
                shift64 <<= shift;
                quotient.lo |= shift64;
            }
        }

        if (shift == 0) break;
        current = uint128_shr(current, 1);
        shift--;
    }

    if (remain) *remain = remainder;
    return quotient;
}

static uint128_t
uint128_div(uint128_t dividend, uint128_t divisor) {
    return uint128_div_internal(dividend, divisor, NULL);
}

static uint128_t
uint128_mod(const uint128_t dividend, const uint128_t divisor) {
    uint128_t remainder;
    uint128_div_internal(dividend, divisor, &remainder);
    return remainder;
}

static int
uint128_bool(const uint128_t a) {
    return (a.hi != 0 || a.lo != 0);
}
#endif

/* Pack a 32-bit unsigned integer from a buffer in big-endian format. */
static uint32_t
pack_u32_be(const unsigned char *buffer, uint32_t t) {
    uint32_t value = 0;
    uint32_t bit_offset = (t * 32);
    uint32_t bit_maximum = bit_offset + 32;

    for (; bit_offset + CHAR_BIT <= bit_maximum; bit_offset += CHAR_BIT) {
        value = (value << CHAR_BIT) | (uint32_t) buffer[bit_offset / CHAR_BIT];
    }

    if (bit_offset < bit_maximum) {
        value = (value << CHAR_BIT) | (uint32_t) (buffer[bit_offset / CHAR_BIT] & ~(UCHAR_MAX >> (CHAR_BIT - (bit_maximum - bit_offset))));
    }

    return value;
}

/* Pack a 64-bit unsigned integer from a buffer in big-endian format. */
static uint64_t
pack_u64_be(const unsigned char *buffer, uint32_t t) {
    uint64_t value = 0;
    uint32_t bit_offset = (t * 64);
    uint32_t bit_maximum = bit_offset + 64;

    for (; bit_offset + CHAR_BIT <= bit_maximum; bit_offset += CHAR_BIT) {
        value = (value << CHAR_BIT) | (uint64_t) buffer[bit_offset / CHAR_BIT];
    }

    if (bit_offset < bit_maximum) {
        value = (value << CHAR_BIT) | (uint64_t) (buffer[bit_offset / CHAR_BIT] & ~(UCHAR_MAX >> (CHAR_BIT - (bit_maximum - bit_offset))));
    }

    return value;
}

/* Write a 32-bit unsigned integer in big-endian format. */
static void
write_u32_be(uint8_t *buffer, uint32_t value) {
    buffer[0] = (uint8_t) ((value >> 24) & UINT8_MAX);
    buffer[1] = (uint8_t) ((value >> 16) & UINT8_MAX);
    buffer[2] = (uint8_t) ((value >> 8) & UINT8_MAX);
    buffer[3] = (uint8_t) ((value >> 0) & UINT8_MAX);
}

/* Write a 64-bit unsigned integer in big-endian format. */
static void
write_u64_be(uint8_t *buffer, uint64_t value) {
    write_u32_be(buffer + 0, (uint32_t) (value >> 32));
    write_u32_be(buffer + 4, (uint32_t) (value & UINT32_MAX));
}

/* [§2.2.2] */
#if defined(_WIN32)
#include <stdlib.h>
#define ROTL32 _rotl
#define ROTR32 _rotr
#define ROTR64 _rotr64
#elif defined(__clang__)
#define ROTL32 __builtin_rotateleft32
#define ROTR32 __builtin_rotateright32
#define ROTR64 __builtin_rotateright64
#else
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#endif
#define SHR(x, n) ((x) >> (n))

/* [§4.1.1] */
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Parity(x, y, z) ((x) ^ (y) ^ (z))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/* [§4.1.2] */
#define Sigma_0_256(x) (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define Sigma_1_256(x) (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define sigma_0_256(x) (ROTR32(x, 7) ^ ROTR32(x, 18) ^ SHR(x, 3))
#define sigma_1_256(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ SHR(x, 10))

/* [§4.1.3] */
#define Sigma_0_512(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define Sigma_1_512(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define sigma_0_512(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ SHR(x, 7))
#define sigma_1_512(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ SHR(x, 6))

#if 0
#include <stdio.h>

static void
buffer_debug_func(const char *func, const unsigned char *buffer, size_t size) {
    fprintf(stderr, "[%s] [size=%zu]\n", func, size);
    for (size_t index = 0; index < (size + CHAR_BIT - 1) / CHAR_BIT; ++index) {
        if (index != 0 && index % 32 == 0) {
            fputs("\n", stderr);
        } else if (index != 0 && index % 4 == 0) {
            fputs(" ", stderr);
        }
        fprintf(stderr, "%02x", buffer[index]);
    }
    fputs("\n", stderr);
}

#define buffer_debug(buffer_) buffer_debug_func(__func__, buffer_, sizeof(buffer_) * CHAR_BIT)
#else
#define buffer_debug(buffer_)
#endif

static void
sha_cpy64(unsigned char *dst, uint32_t dst_index, const unsigned char *src, uint64_t src_index, uint64_t length) {
    if ((dst_index % CHAR_BIT) || (src_index % CHAR_BIT)) {
        unsigned dst_rshift = dst_index % CHAR_BIT;
        unsigned dst_lshift = CHAR_BIT - dst_rshift;

        unsigned src_lshift = src_index % CHAR_BIT;
        unsigned src_rshift = CHAR_BIT - src_lshift;

        uint64_t index;
        uint64_t buffer_index;
        unsigned char chunk_byte;

        for (index = 0; index + CHAR_BIT < length; index += CHAR_BIT) {
            chunk_byte = (src[(src_index + index) / CHAR_BIT] << src_lshift) & UCHAR_MAX;
            chunk_byte |= src[(src_index + index + CHAR_BIT) / CHAR_BIT] >> src_rshift;

            buffer_index = (((uint64_t) dst_index) + index) / CHAR_BIT;
            if (src_index) {
                dst[buffer_index] = (chunk_byte >> dst_rshift);
            } else {
                dst[buffer_index] |= (chunk_byte >> dst_rshift);
            }
            dst[buffer_index + 1] = (chunk_byte << dst_lshift) & UCHAR_MAX;
        }

        chunk_byte = (src[(src_index + index) / CHAR_BIT] << src_lshift) & UCHAR_MAX;
        chunk_byte |= src[(src_index + index + CHAR_BIT) / CHAR_BIT] >> src_rshift;
        dst[((uint64_t) dst_index + index) / CHAR_BIT] |= (chunk_byte >> dst_rshift);
    } else {
        unsigned dst_rem;
        memcpy(
            dst + (dst_index / CHAR_BIT),
            src + (src_index / CHAR_BIT),
            (length + (CHAR_BIT - 1)) / CHAR_BIT
        );

        dst_rem = (unsigned) (((uint64_t) dst_index + length) % CHAR_BIT);
        if (dst_rem) dst[((uint64_t) dst_index + length) / CHAR_BIT] &= (unsigned char) ~(UCHAR_MAX >> dst_rem);
    }
}

static void
sha_cpy128(unsigned char *dst, uint32_t dst_index, const unsigned char *src, uint128_t src_index, uint128_t length) {
    if ((dst_index % CHAR_BIT) || uint128_bool(uint128_mod(src_index, UINT128_CHARBIT))) {
        unsigned dst_rshift = dst_index % CHAR_BIT;
        unsigned dst_lshift = CHAR_BIT - dst_rshift;

        unsigned src_lshift = (unsigned) uint128_u64(uint128_mod(src_index, UINT128_CHARBIT));
        unsigned src_rshift = CHAR_BIT - src_lshift;

        uint128_t index;
        uint64_t buffer_index;
        unsigned char chunk_byte;

        UINT128_DINIT(dst_base, 0, dst_index);

        for (index = UINT128_0; uint128_lt(uint128_add(index, UINT128_CHARBIT), length); index = uint128_add(index, UINT128_CHARBIT)) {
            chunk_byte = (src[uint128_u64(uint128_div(uint128_add(src_index, index), UINT128_CHARBIT))] << src_lshift) & UCHAR_MAX;
            chunk_byte |= src[uint128_u64(uint128_div(uint128_add(uint128_add(src_index, index), UINT128_CHARBIT), UINT128_CHARBIT))] >> src_rshift;

            buffer_index = uint128_u64(uint128_div(uint128_add(dst_base, index), UINT128_CHARBIT));
            if (uint128_gt(src_index, UINT128_0)) {
                dst[buffer_index] = (chunk_byte >> dst_rshift);
            } else {
                dst[buffer_index] |= (chunk_byte >> dst_rshift);
            }
            dst[buffer_index + 1] = (chunk_byte << dst_lshift) & UCHAR_MAX;
        }

        chunk_byte = (src[uint128_u64(uint128_div(uint128_add(src_index, index), UINT128_CHARBIT))] << src_lshift) & UCHAR_MAX;
        chunk_byte |= src[uint128_u64(uint128_div(uint128_add(uint128_add(src_index, index), UINT128_CHARBIT), UINT128_CHARBIT))] >> src_rshift;
        dst[uint128_u64(uint128_div(uint128_add(dst_base, index), UINT128_CHARBIT))] |= (chunk_byte >> dst_rshift);
    } else {
        unsigned dst_rem;

        UINT128_DECL(length_padding);
        UINT128_DECL(dst_base);

        UINT128_INIT(length_padding, 0, CHAR_BIT - 1);
        UINT128_INIT(dst_base, 0, dst_index);

        memcpy(
            dst + (dst_index / CHAR_BIT),
            src + uint128_u64(uint128_div(src_index, UINT128_CHARBIT)),
            uint128_u64(uint128_div(uint128_add(length, length_padding), UINT128_CHARBIT))
        );

        dst_rem = (unsigned) uint128_u64(uint128_mod(uint128_add(dst_base, length), UINT128_CHARBIT));
        if (dst_rem) dst[uint128_u64(uint128_div(uint128_add(dst_base, length), UINT128_CHARBIT))] &= (unsigned char) ~(UCHAR_MAX >> dst_rem);
    }
}

static void
sha_final64(unsigned char *buffer, size_t buffer_bits, uint64_t length) {
    size_t buffer_bytes = (buffer_bits + (CHAR_BIT - 1)) / CHAR_BIT;
    size_t length_bytes = sizeof(length);
    size_t index;

    unsigned char *base = buffer + (buffer_bits - 64 + (CHAR_BIT - 1)) / CHAR_BIT;
    unsigned rshift = (buffer_bits - 64) % CHAR_BIT;

    memset(buffer, 0, buffer_bytes);
    buffer[0] = 1 << (CHAR_BIT - 1);

    if (rshift) {
        unsigned lshift = CHAR_BIT - rshift;

        for (index = 0; index < length_bytes; ++index) {
            unsigned char byte = (length >> (CHAR_BIT * index)) & UCHAR_MAX;
            base[(length_bytes - index) - 1] |= ((byte << lshift) & UCHAR_MAX);
            base[(length_bytes - index) - 2] |= (byte >> rshift);
        }
    } else {
        for (index = 0; index < length_bytes; ++index) {
            unsigned char byte = (length >> (CHAR_BIT * index)) & UCHAR_MAX;
            base[(length_bytes - index) - 1] |= byte;
        }
    }
}

static void
sha_final128(unsigned char *buffer, size_t buffer_bits, uint128_t length) {
    size_t buffer_bytes = (buffer_bits + (CHAR_BIT - 1)) / CHAR_BIT;
    size_t length_bytes = sizeof(length);
    size_t index;

    unsigned char *base = buffer + (buffer_bits - 128 + (CHAR_BIT - 1)) / CHAR_BIT;
    unsigned rshift = (buffer_bits - 128) % CHAR_BIT;

    UINT128_DINIT(uchar_max, 0, UCHAR_MAX);

    memset(buffer, 0, buffer_bytes);
    buffer[0] = 1 << (CHAR_BIT - 1);

    if (rshift) {
        unsigned lshift = CHAR_BIT - rshift;

        for (index = 0; index < length_bytes; ++index) {
            unsigned char byte = (unsigned char) uint128_u64(uint128_and(uint128_shr(length, (unsigned) (CHAR_BIT * index)), uchar_max));
            base[(length_bytes - index) - 1] |= ((byte << lshift) & UCHAR_MAX);
            base[(length_bytes - index) - 2] |= (byte >> rshift);
        }
    } else {
        for (index = 0; index < length_bytes; ++index) {
            unsigned char byte = (unsigned char) uint128_u64(uint128_and(uint128_shr(length, (unsigned) (CHAR_BIT * index)), uchar_max));
            base[(length_bytes - index) - 1] |= byte;
        }
    }
}

static void
sha1_chunk(sha1_ctx_t *ctx) {
    /* [§4.2.1] */
    static const alignas(64) uint32_t K[4] = {
        0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
    };

    /* [§6.2.2] */
    uint32_t W[80];
    uint32_t t;
    uint32_t index;

    buffer_debug(ctx->buffer);
    for (t = 0; t < 16; ++t) W[t] = pack_u32_be(ctx->buffer, t);
    for (; t < 80; ++t) W[t] = ROTL32(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);

    memcpy(ctx->working, ctx->state, 5 * sizeof(uint32_t));

    for (t = 0; t < 80; ++t) {
        uint32_t T = ROTL32(ctx->working[0], 5) + ctx->working[4] + W[t];
        if (t < 20) {
            T += Ch(ctx->working[1], ctx->working[2], ctx->working[3]) + K[0];
        } else if (t < 40) {
            T += Parity(ctx->working[1], ctx->working[2], ctx->working[3]) + K[1];
        } else if (t < 60) {
            T += Maj(ctx->working[1], ctx->working[2], ctx->working[3]) + K[2];
        } else {
            T += Parity(ctx->working[1], ctx->working[2], ctx->working[3]) + K[3];
        }

        memmove(ctx->working + 1, ctx->working, 4 * sizeof(uint32_t));
        ctx->working[2] = ROTL32(ctx->working[2], 30);
        ctx->working[0] = T;
    }

    for (index = 0; index < 5; ++index) {
        ctx->state[index] += ctx->working[index];
    }
}

void
sha1_init(sha1_ctx_t *ctx) {
    /* [§5.3.1] */
    uint32_t state[5] = {
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
    };

    memset(ctx, 0, sizeof(sha1_ctx_t));
    memcpy(ctx->state, state, sizeof(state));
}

void
sha1_update(sha1_ctx_t *ctx, const unsigned char *src, uint64_t src_length) {
    uint64_t src_index = 0;

    while (src_index < src_length) {
        int chunk = 0;
        uint32_t dst_index = ctx->length % 512;
        uint64_t src_rem = src_length - src_index;

        uint64_t length;
        if (src_rem < 512 - dst_index) {
            length = src_rem;
        } else {
            chunk = 1;
            length = (uint64_t) (512 - dst_index);
        }

        sha_cpy64(ctx->buffer, dst_index, src, src_index, length);

        ctx->length += length;
        src_index += length;
        if (chunk) sha1_chunk(ctx);
    }
}

void
sha1_final(sha1_ctx_t *ctx, uint8_t digest[20]) {
    uint32_t dst_index = ctx->length % 512;
    uint32_t buffer_bits = (512 - dst_index) + (dst_index >= 448 ? 512 : 0);
    uint32_t index;

    VLA_DINIT(unsigned char, buffer, (buffer_bits + (CHAR_BIT - 1)) / CHAR_BIT);
    sha_final64(buffer, buffer_bits, ctx->length);

    buffer_debug(buffer);
    sha1_update(ctx, buffer, buffer_bits);

    for (index = 0; index < 5; ++index) {
        write_u32_be(digest + index * 4, ctx->state[index]);
    }

    memzero(ctx, sizeof(sha1_ctx_t));
    memzero(buffer, sizeof(buffer));
    VLA_FREE(buffer);
}

static void
sha256_base_chunk(sha256_base_ctx_t *ctx) {
    /* [§4.2.2] */
    static const alignas(64) uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    /* [§6.2.2] */
    uint32_t W[64];
    uint32_t t;
    uint32_t index;

    buffer_debug(ctx->buffer);
    for (t = 0; t < 16; ++t) W[t] = pack_u32_be(ctx->buffer, t);
    for (; t < 64; ++t) W[t] = sigma_1_256(W[t - 2]) + W[t - 7] + sigma_0_256(W[t - 15]) + W[t - 16];

    memcpy(ctx->working, ctx->state, 8 * sizeof(uint32_t));

    for (t = 0; t < 64; ++t) {
        uint32_t T1 = ctx->working[7] + Sigma_1_256(ctx->working[4]) + Ch(ctx->working[4], ctx->working[5], ctx->working[6]) + K[t] + W[t];
        uint32_t T2 = Sigma_0_256(ctx->working[0]) + Maj(ctx->working[0], ctx->working[1], ctx->working[2]);

        memmove(ctx->working + 1, ctx->working, 7 * sizeof(uint32_t));
        ctx->working[4] += T1;
        ctx->working[0] = T1 + T2;
    }

    for (index = 0; index < 8; ++index) {
        ctx->state[index] += ctx->working[index];
    }
}

static void
sha256_base_update(sha256_base_ctx_t *ctx, const unsigned char *src, uint64_t src_length) {
    uint64_t src_index = 0;

    while (src_index < src_length) {
        int chunk = 0;
        uint32_t dst_index = ctx->length % 512;
        uint64_t src_rem = src_length - src_index;

        uint64_t length;
        if (src_rem < 512 - dst_index) {
            length = src_rem;
        } else {
            chunk = 1;
            length = (uint64_t) (512 - dst_index);
        }

        sha_cpy64(ctx->buffer, dst_index, src, src_index, length);

        ctx->length += length;
        src_index += length;
        if (chunk) sha256_base_chunk(ctx);
    }
}

void
sha224_init(sha224_ctx_t *ctx) {
    /* [§5.3.2] */
    uint32_t state[8] = {
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
    };

    memset(ctx, 0, sizeof(sha224_ctx_t));
    memcpy(ctx->base.state, state, sizeof(state));
}

void
sha224_update(sha224_ctx_t *ctx, const unsigned char *src, uint64_t length) {
    sha256_base_update(&ctx->base, src, length);
}

void
sha224_final(sha224_ctx_t *ctx, uint8_t digest[28]) {
    uint32_t dst_index = ctx->base.length % 512;
    uint32_t buffer_bits = (512 - dst_index) + (dst_index >= 448 ? 512 : 0);
    uint32_t index;

    VLA_DINIT(unsigned char, buffer, (buffer_bits + (CHAR_BIT - 1)) / CHAR_BIT);
    sha_final64(buffer, buffer_bits, ctx->base.length);

    buffer_debug(buffer);
    sha224_update(ctx, buffer, buffer_bits);

    for (index = 0; index < 7; ++index) {
        write_u32_be(digest + index * 4, ctx->base.state[index]);
    }

    memzero(ctx, sizeof(sha224_ctx_t));
    memzero(buffer, sizeof(buffer));
    VLA_FREE(buffer);
}

void
sha256_init(sha256_ctx_t *ctx) {
    /* [§5.3.3] */
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    memset(ctx, 0, sizeof(sha256_ctx_t));
    memcpy(ctx->base.state, state, sizeof(state));
}

void
sha256_update(sha256_ctx_t *ctx, const unsigned char *src, uint64_t length) {
    sha256_base_update(&ctx->base, src, length);
}

void
sha256_final(sha256_ctx_t *ctx, uint8_t digest[32]) {
    uint32_t dst_index = ctx->base.length % 512;
    uint32_t buffer_bits = (512 - dst_index) + (dst_index >= 448 ? 512 : 0);
    uint32_t index;

    VLA_DINIT(unsigned char, buffer, (buffer_bits + (CHAR_BIT - 1)) / CHAR_BIT);
    sha_final64(buffer, buffer_bits, ctx->base.length);

    buffer_debug(buffer);
    sha256_update(ctx, buffer, buffer_bits);

    for (index = 0; index < 8; ++index) {
        write_u32_be(digest + index * 4, ctx->base.state[index]);
    }

    memzero(ctx, sizeof(sha256_ctx_t));
    memzero(buffer, sizeof(buffer));
    VLA_FREE(buffer);
}

static void
sha512_base_chunk(sha512_base_ctx_t *ctx) {
    /* [§4.2.3] */
    static const alignas(64) uint64_t K[80] = {
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    };

    /* [§6.4.2] */
    uint64_t W[80];
    uint32_t t;
    uint64_t index;

    buffer_debug(ctx->buffer);
    for (t = 0; t < 16; ++t) W[t] = pack_u64_be(ctx->buffer, t);
    for (; t < 80; ++t) W[t] = sigma_1_512(W[t - 2]) + W[t - 7] + sigma_0_512(W[t - 15]) + W[t - 16];

    memcpy(ctx->working, ctx->state, 8 * sizeof(uint64_t));

    for (t = 0; t < 80; ++t) {
        uint64_t T1 = ctx->working[7] + Sigma_1_512(ctx->working[4]) + Ch(ctx->working[4], ctx->working[5], ctx->working[6]) + K[t] + W[t];
        uint64_t T2 = Sigma_0_512(ctx->working[0]) + Maj(ctx->working[0], ctx->working[1], ctx->working[2]);

        memmove(ctx->working + 1, ctx->working, 7 * sizeof(uint64_t));
        ctx->working[4] += T1;
        ctx->working[0] = T1 + T2;
    }

    for (index = 0; index < 8; ++index) {
        ctx->state[index] += ctx->working[index];
    }
}

static void
sha512_base_update(sha512_base_ctx_t *ctx, const unsigned char *src, uint128_t src_length) {
    uint128_t src_index = UINT128_0;

    while (uint128_lt(src_index, src_length)) {
        int chunk = 0;
        uint32_t dst_index = (uint32_t) uint128_u64(uint128_mod(ctx->length, UINT128_1024));
        uint128_t src_rem = uint128_sub(src_length, src_index);

        uint128_t length;
        UINT128_DINIT(chunk_length, 0, 1024 - dst_index);

        if (uint128_lt(src_rem, chunk_length)) {
            length = src_rem;
        } else {
            chunk = 1;
            length = chunk_length;
        }

        sha_cpy128(ctx->buffer, dst_index, src, src_index, length);

        ctx->length = uint128_add(ctx->length, length);
        src_index = uint128_add(src_index, length);
        if (chunk) sha512_base_chunk(ctx);
    }
}

void
sha384_init(sha384_ctx_t *ctx) {
    /* [§5.3.4] */
    uint64_t state[8] = {
        0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
        0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
    };

    memset(ctx, 0, sizeof(sha384_ctx_t));
    memcpy(ctx->base.state, state, sizeof(state));
}

void
sha384_update(sha384_ctx_t *ctx, const unsigned char *src, uint128_t length) {
    sha512_base_update(&ctx->base, src, length);
}

void
sha384_final(sha384_ctx_t *ctx, uint8_t digest[48]) {
    uint32_t dst_index = (uint32_t) uint128_u64(uint128_mod(ctx->base.length, UINT128_1024));
    uint32_t buffer_bits = (1024 - dst_index) + (dst_index >= 896 ? 1024 : 0);
    uint32_t index;

    UINT128_DECL(length);
    VLA_DECL(unsigned char, buffer, (buffer_bits + (CHAR_BIT - 1)) / CHAR_BIT);

    UINT128_INIT(length, 0, buffer_bits);
    VLA_INIT(unsigned char, buffer, (buffer_bits + (CHAR_BIT - 1)) / CHAR_BIT);

    sha_final128(buffer, buffer_bits, ctx->base.length);

    buffer_debug(buffer);
    sha512_base_update(&ctx->base, buffer, length);

    for (index = 0; index < 6; ++index) {
        write_u64_be(digest + index * 8, ctx->base.state[index]);
    }

    memzero(ctx, sizeof(sha384_ctx_t));
    memzero(buffer, sizeof(buffer));
    VLA_FREE(buffer);
}

void
sha512_init(sha512_ctx_t *ctx) {
    /* [§5.3.5] */
    uint64_t state[8] = {
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    };

    memset(ctx, 0, sizeof(sha512_ctx_t));
    memcpy(ctx->base.state, state, sizeof(state));
}

void
sha512_update(sha512_ctx_t *ctx, const unsigned char *src, uint128_t length) {
    sha512_base_update(&ctx->base, src, length);
}

void
sha512_final(sha512_ctx_t *ctx, uint8_t digest[64]) {
    uint32_t dst_index = (uint32_t) uint128_u64(uint128_mod(ctx->base.length, UINT128_1024));
    uint32_t buffer_bits = (1024 - dst_index) + (dst_index >= 896 ? 1024 : 0);
    uint32_t index;

    UINT128_DECL(length);
    VLA_DECL(unsigned char, buffer, (buffer_bits + (CHAR_BIT - 1)) / CHAR_BIT);

    UINT128_INIT(length, 0, buffer_bits);
    VLA_INIT(unsigned char, buffer, (buffer_bits + (CHAR_BIT - 1)) / CHAR_BIT);

    sha_final128(buffer, buffer_bits, ctx->base.length);

    buffer_debug(buffer);
    sha512_base_update(&ctx->base, buffer, length);

    for (index = 0; index < 8; ++index) {
        write_u64_be(digest + index * 8, ctx->base.state[index]);
    }

    memzero(ctx, sizeof(sha512_ctx_t));
    memzero(buffer, sizeof(buffer));
    VLA_FREE(buffer);
}

void
sha512_224_init(sha512_224_ctx_t *ctx) {
    /* [§5.3.6.1] */
    uint64_t state[8] = {
        0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
        0x0f6d2b697bd44da8, 0x77e36f7304c48942, 0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1
    };

    memset(ctx, 0, sizeof(sha512_224_ctx_t));
    memcpy(ctx->base.state, state, sizeof(state));
}

void
sha512_224_update(sha512_224_ctx_t *ctx, const unsigned char *src, uint128_t length) {
    sha512_base_update(&ctx->base, src, length);
}

void
sha512_224_final(sha512_224_ctx_t *ctx, uint8_t digest[28]) {
    uint32_t dst_index = (uint32_t) uint128_u64(uint128_mod(ctx->base.length, UINT128_1024));
    uint32_t buffer_bits = (1024 - dst_index) + (dst_index >= 896 ? 1024 : 0);
    uint32_t index;

    UINT128_DECL(length);
    VLA_DECL(unsigned char, buffer, (buffer_bits + (CHAR_BIT - 1)) / CHAR_BIT);

    UINT128_INIT(length, 0, buffer_bits);
    VLA_INIT(unsigned char, buffer, (buffer_bits + (CHAR_BIT - 1)) / CHAR_BIT);

    sha_final128(buffer, buffer_bits, ctx->base.length);

    buffer_debug(buffer);
    sha512_base_update(&ctx->base, buffer, length);

    for (index = 0; index < 3; ++index) {
        write_u64_be(digest + index * 8, ctx->base.state[index]);
    }
    write_u32_be(digest + 24, (uint32_t) (ctx->base.state[3] >> 32));

    memzero(ctx, sizeof(sha512_224_ctx_t));
    memzero(buffer, sizeof(buffer));
    VLA_FREE(buffer);
}

void
sha512_256_init(sha512_256_ctx_t *ctx) {
    /* [§5.3.6.2] */
    uint64_t state[8] = {
        0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd,
        0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2
    };

    memset(ctx, 0, sizeof(sha512_256_ctx_t));
    memcpy(ctx->base.state, state, sizeof(state));
}

void
sha512_256_update(sha512_256_ctx_t *ctx, const unsigned char *src, uint128_t length) {
    sha512_base_update(&ctx->base, src, length);
}

void
sha512_256_final(sha512_256_ctx_t *ctx, uint8_t digest[32]) {
    uint32_t dst_index = (uint32_t) uint128_u64(uint128_mod(ctx->base.length, UINT128_1024));
    uint32_t buffer_bits = (1024 - dst_index) + (dst_index >= 896 ? 1024 : 0);
    uint32_t index;

    UINT128_DECL(length);
    VLA_DECL(unsigned char, buffer, (buffer_bits + (CHAR_BIT - 1)) / CHAR_BIT);

    UINT128_INIT(length, 0, buffer_bits);
    VLA_INIT(unsigned char, buffer, (buffer_bits + (CHAR_BIT - 1)) / CHAR_BIT);

    sha_final128(buffer, buffer_bits, ctx->base.length);

    buffer_debug(buffer);
    sha512_base_update(&ctx->base, buffer, length);

    for (index = 0; index < 4; ++index) {
        write_u64_be(digest + index * 8, ctx->base.state[index]);
    }

    memzero(ctx, sizeof(sha512_256_ctx_t));
    memzero(buffer, sizeof(buffer));
    VLA_FREE(buffer);
}
