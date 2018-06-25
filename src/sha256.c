/*	$OpenBSD: sha2.c,v 1.12 2008/09/06 12:00:19 djm Exp $	*/

/*
 * FILE:	sha2.c
 * AUTHOR:	Aaron D. Gifford <me@aarongifford.com>
 *
 * Copyright (c) 2000-2001, Aaron D. Gifford
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $From: sha2.c,v 1.1 2001/11/08 00:01:51 adg Exp adg $
 */

#include "sha256.h"
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define SHA512_BLOCK_LENGTH 128

typedef struct _SHA2_CTX {
    union {
        uint32_t st32[8];
        uint64_t st64[8];
    } state;
    uint64_t bitcount[2];
    uint8_t buffer[SHA512_BLOCK_LENGTH];
} SHA2_CTX;

#define SHA256_SHORT_BLOCK_LENGTH (SHA256_BLOCK_LENGTH - 8)

#define BE_8_TO_32(dst, cp)                                                    \
    do {                                                                       \
        (dst) = (uint32_t)(cp)[3] | ((uint32_t)(cp)[2] << 8) |                 \
                ((uint32_t)(cp)[1] << 16) | ((uint32_t)(cp)[0] << 24);         \
    } while (0)

#define BE_64_TO_8(cp, src)                                                    \
    do {                                                                       \
        (cp)[0] = (src) >> 56;                                                 \
        (cp)[1] = (src) >> 48;                                                 \
        (cp)[2] = (src) >> 40;                                                 \
        (cp)[3] = (src) >> 32;                                                 \
        (cp)[4] = (src) >> 24;                                                 \
        (cp)[5] = (src) >> 16;                                                 \
        (cp)[6] = (src) >> 8;                                                  \
        (cp)[7] = (src);                                                       \
    } while (0)

#define BE_32_TO_8(cp, src)                                                    \
    do {                                                                       \
        (cp)[0] = (src) >> 24;                                                 \
        (cp)[1] = (src) >> 16;                                                 \
        (cp)[2] = (src) >> 8;                                                  \
        (cp)[3] = (src);                                                       \
    } while (0)

/* Shift-right (used in SHA-256, SHA-384, and SHA-512): */
#define R(b, x) ((x) >> (b))
/* 32-bit Rotate-right (used in SHA-256): */
#define S32(b, x) (((x) >> (b)) | ((x) << (32 - (b))))

/* Two of six logical functions used in SHA-256, SHA-384, and SHA-512: */
#define Ch(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/* Four of six logical functions used in SHA-256: */
#define Sigma0_256(x) (S32(2, (x)) ^ S32(13, (x)) ^ S32(22, (x)))
#define Sigma1_256(x) (S32(6, (x)) ^ S32(11, (x)) ^ S32(25, (x)))
#define sigma0_256(x) (S32(7, (x)) ^ S32(18, (x)) ^ R(3, (x)))
#define sigma1_256(x) (S32(17, (x)) ^ S32(19, (x)) ^ R(10, (x)))

/*** SHA-XYZ INITIAL HASH VALUES AND CONSTANTS ************************/
/* Hash constant words K for SHA-256: */
static const uint32_t K256[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
    0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
    0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
    0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
    0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
    0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
    0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
    0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
    0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
    0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL};

/* Initial hash value H for SHA-256: */
static const uint32_t sha256_initial_hash_value[8] = {
    0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
    0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL};

static void
SHA256Init(SHA2_CTX *context)
{
    if (context == NULL)
        return;
    memcpy(context->state.st32, sha256_initial_hash_value,
           sizeof(sha256_initial_hash_value));
    memset(context->buffer, 0, sizeof(context->buffer));
    context->bitcount[0] = 0;
}

static void
SHA256Transform(uint32_t state[8], const uint8_t data[SHA256_BLOCK_LENGTH])
{
    uint32_t a, b, c, d, e, f, g, h, s0, s1;
    uint32_t T1, T2, W256[16];
    int j;

    /* Initialize registers with the prev. intermediate value */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    j = 0;
    do {
        BE_8_TO_32(W256[j], data);
        data += 4;
        /* Apply the SHA-256 compression function to update a..h */
        T1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[j] + W256[j];
        T2 = Sigma0_256(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;

        j++;
    } while (j < 16);

    do {
        /* Part of the message block expansion: */
        s0 = W256[(j + 1) & 0x0f];
        s0 = sigma0_256(s0);
        s1 = W256[(j + 14) & 0x0f];
        s1 = sigma1_256(s1);

        /* Apply the SHA-256 compression function to update a..h */
        T1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[j] +
             (W256[j & 0x0f] += s1 + W256[(j + 9) & 0x0f] + s0);
        T2 = Sigma0_256(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;

        j++;
    } while (j < 64);

    /* Compute the current intermediate hash value */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;

    /* Clean up */
    a = b = c = d = e = f = g = h = T1 = T2 = 0;
}

static void
SHA256Update(SHA2_CTX *context, const uint8_t *data, size_t len)
{
    size_t freespace, usedspace;

    /* Calling with no data is valid (we do nothing) */
    if (len == 0)
        return;

    usedspace = (context->bitcount[0] >> 3) % SHA256_BLOCK_LENGTH;
    if (usedspace > 0) {
        /* Calculate how much free space is available in the buffer */
        freespace = SHA256_BLOCK_LENGTH - usedspace;

        if (len >= freespace) {
            /* Fill the buffer completely and process it */
            memcpy(&context->buffer[usedspace], data, freespace);
            context->bitcount[0] += freespace << 3;
            len -= freespace;
            data += freespace;
            SHA256Transform(context->state.st32, context->buffer);
        } else {
            /* The buffer is not yet full */
            memcpy(&context->buffer[usedspace], data, len);
            context->bitcount[0] += len << 3;
            /* Clean up: */
            usedspace = freespace = 0;
            return;
        }
    }
    while (len >= SHA256_BLOCK_LENGTH) {
        /* Process as many complete blocks as we can */
        SHA256Transform(context->state.st32, data);
        context->bitcount[0] += SHA256_BLOCK_LENGTH << 3;
        len -= SHA256_BLOCK_LENGTH;
        data += SHA256_BLOCK_LENGTH;
    }
    if (len > 0) {
        /* There's left-overs, so save 'em */
        memcpy(context->buffer, data, len);
        context->bitcount[0] += len << 3;
    }
    /* Clean up: */
    usedspace = freespace = 0;
}

static void
SHA256Pad(SHA2_CTX *context)
{
    unsigned int usedspace;

    usedspace = (context->bitcount[0] >> 3) % SHA256_BLOCK_LENGTH;
    if (usedspace > 0) {
        /* Begin padding with a 1 bit: */
        context->buffer[usedspace++] = 0x80;

        if (usedspace <= SHA256_SHORT_BLOCK_LENGTH) {
            /* Set-up for the last transform: */
            memset(&context->buffer[usedspace], 0,
                   SHA256_SHORT_BLOCK_LENGTH - usedspace);
        } else {
            if (usedspace < SHA256_BLOCK_LENGTH) {
                memset(&context->buffer[usedspace], 0,
                       SHA256_BLOCK_LENGTH - usedspace);
            }
            /* Do second-to-last transform: */
            SHA256Transform(context->state.st32, context->buffer);

            /* Prepare for last transform: */
            memset(context->buffer, 0, SHA256_SHORT_BLOCK_LENGTH);
        }
    } else {
        /* Set-up for the last transform: */
        memset(context->buffer, 0, SHA256_SHORT_BLOCK_LENGTH);

        /* Begin padding with a 1 bit: */
        *context->buffer = 0x80;
    }
    /* Store the length of input data (in bits) in big endian format: */
    BE_64_TO_8(&context->buffer[SHA256_SHORT_BLOCK_LENGTH],
               context->bitcount[0]);

    /* Final transform: */
    SHA256Transform(context->state.st32, context->buffer);

    /* Clean up: */
    usedspace = 0;
}

static void
SHA256Final(uint8_t digest[SHA256_DIGEST_LENGTH], SHA2_CTX *context)
{
    SHA256Pad(context);

    /* If no digest buffer is passed, we don't bother doing this: */
    if (digest != NULL) {
        /* Convert TO host byte order */
        for (int i = 0; i < 8; i++)
            BE_32_TO_8(digest + i * 4, context->state.st32[i]);

        memset(context, 0, sizeof(*context));
    }
}

static char *
SHA256End(SHA2_CTX *ctx, char *buf, size_t digest_length)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    static const char hex[] = "0123456789abcdef";

    if (buf == NULL || digest_length > SHA256_DIGEST_LENGTH)
        return NULL;

    SHA256Final(digest, ctx);
    for (size_t i = 0; i < digest_length; i++) {
        buf[i + i] = hex[digest[i] >> 4];
        buf[i + i + 1] = hex[digest[i] & 0x0f];
    }
    buf[digest_length * 2] = '\0';
#if 0
    // Not needed.
    memset(digest, 0, sizeof(digest));
#endif
    return buf;
}

char *
SHA256Data(const void *data, size_t len, char *digest_string,
           size_t digest_octet_count)
{
    SHA2_CTX ctx;

    SHA256Init(&ctx);
    SHA256Update(&ctx, data, len);
    return SHA256End(&ctx, digest_string, digest_octet_count);
}
