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

// THIS FILE IS MOSTLY COPIED FROM [tiny_sha3](https://github.com/mjosaarinen/tiny_sha3)

#ifndef SHA3_H
#define SHA3_H

#include <stddef.h>
#include <stdint.h>

#ifndef KECCAKF_ROUNDS
#define KECCAKF_ROUNDS 24
#endif

#ifndef ROTL64
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
#endif

// state context
typedef struct {
    union {                                 // state:
        uint8_t b[200];                     // 8-bit bytes
        uint64_t q[25];                     // 64-bit words
    } st;
    int pt, rsiz, mdlen;                    // these don't overflow
} sha3_ctx_t;

// Compression function.
void CSHAKE128_sha3_keccakf(uint64_t st[25]);

// OpenSSL - like interfece
int CSHAKE128_sha3_init(sha3_ctx_t *c, int mdlen);    // mdlen = hash output in bytes
int CSHAKE128_sha3_update(sha3_ctx_t *c, const void *data, size_t len);
int CSHAKE128_sha3_final(void *md, sha3_ctx_t *c);    // digest goes to md

// compute a sha3 hash (md) of given byte length from "in"
void *CSHAKE128_sha3(const void *in, size_t inlen, void *md, int mdlen);

// SHAKE128 and SHAKE256 extensible-output functions
//#define CSHAKE128_shake128_init(c) CSHAKE128_sha3_init(c, 16)
//#define CSHAKE128_shake256_init(c) CSHAKE128_sha3_init(c, 32)
//#define CSHAKE128_shake_update CSHAKE128_sha3_update
int CSHAKE128_shake128_init(sha3_ctx_t *ctx);
int CSHAKE128_shake256_init(sha3_ctx_t *ctx);
int CSHAKE128_shake_update(sha3_ctx_t *ctx, const void *data, size_t len);

void CSHAKE128_shake_xof(sha3_ctx_t *c);
void CSHAKE128_shake_read(sha3_ctx_t *c, void *out, size_t len);

#endif
