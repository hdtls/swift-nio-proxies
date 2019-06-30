//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright © 2019 Netbot Ltd. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#include "CNIOSecurityShims.h"
#include "sodium/crypto_stream_salsa20.h"
#include "sodium/crypto_stream_xsalsa20.h"
#include "sodium/crypto_stream_chacha20.h"
#include "sodium/crypto_stream_xchacha20.h"
#include "sodium/crypto_aead_aes256gcm.h"
#include "sodium/crypto_aead_chacha20poly1305.h"
#include "sodium/crypto_aead_xchacha20poly1305.h"

int CNIOSecurityShims_SECURITY_init(void) {
    return sodium_init();
}

int CNIOSecurityShims_STREAM_salsa20(unsigned char *c, const unsigned char *m,
unsigned long long mlen,
const unsigned char *n, uint64_t ic,
const unsigned char *k) {
    return crypto_stream_salsa20_xor_ic(c, m, mlen, n, ic, k);
}

int CNIOSecurityShims_STREAM_chacha20(unsigned char *c, const unsigned char *m,
unsigned long long mlen,
const unsigned char *n, uint64_t ic,
const unsigned char *k) {
    return crypto_stream_chacha20_xor_ic(c, m, mlen, n, ic, k);
}

int CNIOSecurityShims_STREAM_chacha20_ietf(unsigned char *c, const unsigned char *m,
unsigned long long mlen,
const unsigned char *n, uint64_t ic,
const unsigned char *k) {
    return crypto_stream_chacha20_ietf_xor_ic(c, m, mlen, n, ic, k);
}

int CNIOSecurityShims_STREAM_xchacha20(unsigned char *c, const unsigned char *m,
unsigned long long mlen,
const unsigned char *n, uint64_t ic,
const unsigned char *k) {
    return crypto_stream_xchacha20_xor_ic(c, m, mlen, n, ic, k);
}

int CNIOSecurityShims_AEAD_chacha20poly1305_enc(unsigned char *c,
unsigned long long *clen_p,
const unsigned char *m,
unsigned long long mlen,
const unsigned char *ad,
unsigned long long adlen,
const unsigned char *nsec,
const unsigned char *npub,
const unsigned char *k) {
    return crypto_aead_chacha20poly1305_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k);
}

int CNIOSecurityShims_AEAD_chacha20poly1305_dec(unsigned char *m,
unsigned long long *mlen_p,
unsigned char *nsec,
const unsigned char *c,
unsigned long long clen,
const unsigned char *ad,
unsigned long long adlen,
const unsigned char *npub,
const unsigned char *k) {
    return crypto_aead_chacha20poly1305_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k);
}

int CNIOSecurityShims_AEAD_chacha20poly1305_ietf_enc(unsigned char *c,
unsigned long long *clen_p,
const unsigned char *m,
unsigned long long mlen,
const unsigned char *ad,
unsigned long long adlen,
const unsigned char *nsec,
const unsigned char *npub,
const unsigned char *k) {
    return crypto_aead_chacha20poly1305_ietf_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k);
}

int CNIOSecurityShims_AEAD_chacha20poly1305_ietf_dec(unsigned char *m,
unsigned long long *mlen_p,
unsigned char *nsec,
const unsigned char *c,
unsigned long long clen,
const unsigned char *ad,
unsigned long long adlen,
const unsigned char *npub,
const unsigned char *k) {
    return crypto_aead_chacha20poly1305_ietf_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k);
}

int CNIOSecurityShims_AEAD_xchacha20poly1305_ietf_enc(unsigned char *c,
unsigned long long *clen_p,
const unsigned char *m,
unsigned long long mlen,
const unsigned char *ad,
unsigned long long adlen,
const unsigned char *nsec,
const unsigned char *npub,
const unsigned char *k) {
    return crypto_aead_xchacha20poly1305_ietf_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k);
}

int CNIOSecurityShims_AEAD_xchacha20poly1305_ietf_dec(unsigned char *m,
     unsigned long long *mlen_p,
     unsigned char *nsec,
     const unsigned char *c,
     unsigned long long clen,
     const unsigned char *ad,
     unsigned long long adlen,
     const unsigned char *npub,
const unsigned char *k) {
    return crypto_aead_xchacha20poly1305_ietf_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k);
}

int CNIOSecurityShims_AEAD_aes256gcm_enc(unsigned char *c,
unsigned long long *clen_p,
const unsigned char *m,
unsigned long long mlen,
const unsigned char *ad,
unsigned long long adlen,
const unsigned char *nsec,
const unsigned char *npub,
const unsigned char *k) {
    return crypto_aead_aes256gcm_encrypt(c, clen_p, mlen, mlen, ad, adlen, nsec, npub, k);
}

int CNIOSecurityShims_AEAD_aes256gcm_dec(unsigned char *m,
unsigned long long *mlen_p,
unsigned char *nsec,
const unsigned char *c,
unsigned long long clen,
const unsigned char *ad,
unsigned long long adlen,
const unsigned char *npub,
const unsigned char *k) {
    return crypto_aead_aes256gcm_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k);
}
