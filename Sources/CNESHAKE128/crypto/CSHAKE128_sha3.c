//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// The MIT License (MIT)
//
// Copyright (c) 2015 Markku-Juhani O. Saarinen
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// THIS FILE IS MOSTLY COPIED FROM [swift-nio-extras](https://github.com/apple/swift-nio-extras)

#include "CSHAKE128_sha3.h"

// update the state with given number of rounds

void CSHAKE128_sha3_keccakf(uint64_t st[25])
{
    // constants
    const uint64_t keccakf_rndc[24] = {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    };
    const int keccakf_rotc[24] = {
        1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
        27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };
    const int keccakf_piln[24] = {
        10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };
    
    // variables
    int i, j, r;
    uint64_t t, bc[5];
    
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    uint8_t *v;
    
    // endianess conversion. this is redundant on little-endian targets
    for (i = 0; i < 25; i++) {
        v = (uint8_t *) &st[i];
        st[i] = ((uint64_t) v[0])     | (((uint64_t) v[1]) << 8) |
        (((uint64_t) v[2]) << 16) | (((uint64_t) v[3]) << 24) |
        (((uint64_t) v[4]) << 32) | (((uint64_t) v[5]) << 40) |
        (((uint64_t) v[6]) << 48) | (((uint64_t) v[7]) << 56);
    }
#endif
    
    // actual iteration
    for (r = 0; r < KECCAKF_ROUNDS; r++) {
        
        // Theta
        for (i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        
        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }
        
        // Rho Pi
        t = st[1];
        for (i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }
        
        //  Chi
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
        
        //  Iota
        st[0] ^= keccakf_rndc[r];
    }
    
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    // endianess conversion. this is redundant on little-endian targets
    for (i = 0; i < 25; i++) {
        v = (uint8_t *) &st[i];
        t = st[i];
        v[0] = t & 0xFF;
        v[1] = (t >> 8) & 0xFF;
        v[2] = (t >> 16) & 0xFF;
        v[3] = (t >> 24) & 0xFF;
        v[4] = (t >> 32) & 0xFF;
        v[5] = (t >> 40) & 0xFF;
        v[6] = (t >> 48) & 0xFF;
        v[7] = (t >> 56) & 0xFF;
    }
#endif
}

// Initialize the context for SHA3

int CSHAKE128_sha3_init(sha3_ctx_t *c, int mdlen)
{
    int i;
    
    for (i = 0; i < 25; i++)
        c->st.q[i] = 0;
    c->mdlen = mdlen;
    c->rsiz = 200 - 2 * mdlen;
    c->pt = 0;
    
    return 1;
}

// update state with more data

int CSHAKE128_sha3_update(sha3_ctx_t *c, const void *data, size_t len)
{
    size_t i;
    int j;
    
    j = c->pt;
    for (i = 0; i < len; i++) {
        c->st.b[j++] ^= ((const uint8_t *) data)[i];
        if (j >= c->rsiz) {
            CSHAKE128_sha3_keccakf(c->st.q);
            j = 0;
        }
    }
    c->pt = j;
    
    return 1;
}

// finalize and output a hash

int CSHAKE128_sha3_final(void *md, sha3_ctx_t *c)
{
    int i;
    
    c->st.b[c->pt] ^= 0x06;
    c->st.b[c->rsiz - 1] ^= 0x80;
    CSHAKE128_sha3_keccakf(c->st.q);
    
    for (i = 0; i < c->mdlen; i++) {
        ((uint8_t *) md)[i] = c->st.b[i];
    }
    
    return 1;
}

// compute a SHA-3 hash (md) of given byte length from "in"

void *CSHAKE128_sha3(const void *in, size_t inlen, void *md, int mdlen)
{
    sha3_ctx_t sha3;
    
    CSHAKE128_sha3_init(&sha3, mdlen);
    CSHAKE128_sha3_update(&sha3, in, inlen);
    CSHAKE128_sha3_final(md, &sha3);
    
    return md;
}

int CSHAKE128_shake128_init(sha3_ctx_t *ctx) {
    return CSHAKE128_sha3_init(ctx, 16);
}

int CSHAKE128_shake256_init(sha3_ctx_t *ctx) {
    return CSHAKE128_sha3_init(ctx, 32);
}

int CSHAKE128_shake_update(sha3_ctx_t *ctx, const void *data, size_t len) {
    return CSHAKE128_sha3_update(ctx, data, len);
}

// SHAKE128 and SHAKE256 extensible-output functionality
void CSHAKE128_shake_xof(sha3_ctx_t *c)
{
    c->st.b[c->pt] ^= 0x1F;
    c->st.b[c->rsiz - 1] ^= 0x80;
    CSHAKE128_sha3_keccakf(c->st.q);
    c->pt = 0;
}

void CSHAKE128_shake_read(sha3_ctx_t *c, void *out, size_t len)
{
    size_t i;
    int j;
    
    j = c->pt;
    for (i = 0; i < len; i++) {
        if (j >= c->rsiz) {
            CSHAKE128_sha3_keccakf(c->st.q);
            j = 0;
        }
        ((uint8_t *) out)[i] = c->st.b[j++];
    }
    c->pt = j;
}
