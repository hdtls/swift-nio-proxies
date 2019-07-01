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

#include "CNIOLibsodium/core.h"
#include "CNIOLibsodium/utils.h"
#include "CNIOLibsodium/crypto_stream_salsa20.h"
#include "CNIOLibsodium/crypto_stream_xsalsa20.h"
#include "CNIOLibsodium/crypto_stream_chacha20.h"
#include "CNIOLibsodium/crypto_stream_xchacha20.h"
#include "CNIOLibsodium/crypto_aead_aes256gcm.h"
#include "CNIOLibsodium/crypto_aead_chacha20poly1305.h"
#include "CNIOLibsodium/crypto_aead_xchacha20poly1305.h"

int CNIOSecurityShims_SECURITY_init(void) {
    return sodium_init();
}

void CNIOSecurityShims_SECURITY_INCREMENT(uint8_t *n, const size_t nlen) {
    sodium_increment(n, nlen);
}

int CNIOSecurityShims_STREAM_salsa20(uint8_t *c, const uint8_t *m, uint64_t mlen, const uint8_t *n, uint64_t ic, const uint8_t *k) {
    return crypto_stream_salsa20_xor_ic(c, m, mlen, n, ic, k);
}

int CNIOSecurityShims_STREAM_chacha20(uint8_t *c, const uint8_t *m, uint64_t mlen, const uint8_t *n, uint64_t ic, const uint8_t *k) {
    return crypto_stream_chacha20_xor_ic(c, m, mlen, n, ic, k);
}

int CNIOSecurityShims_STREAM_chacha20_ietf(uint8_t *c, const uint8_t *m, uint64_t mlen, const uint8_t *n, uint64_t ic, const uint8_t *k) {
    return crypto_stream_chacha20_ietf_xor_ic(c, m, mlen, n, ic, k);
}

int CNIOSecurityShims_STREAM_xchacha20(uint8_t *c, const uint8_t *m, uint64_t mlen, const uint8_t *n, uint64_t ic, const uint8_t *k) {
    return crypto_stream_xchacha20_xor_ic(c, m, mlen, n, ic, k);
}

int CNIOSecurityShims_AEAD_chacha20poly1305_enc(uint8_t *c, uint64_t *clen_p, const uint8_t *m, uint64_t mlen, const uint8_t *ad, uint64_t adlen, const uint8_t *nsec, const uint8_t *npub, const uint8_t *k) {
    return crypto_aead_chacha20poly1305_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k);
}

int CNIOSecurityShims_AEAD_chacha20poly1305_dec(uint8_t *m, uint64_t *mlen_p, uint8_t *nsec, const uint8_t *c, uint64_t clen, const uint8_t *ad, uint64_t adlen, const uint8_t *npub, const uint8_t *k) {
    return crypto_aead_chacha20poly1305_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k);
}

int CNIOSecurityShims_AEAD_chacha20poly1305_ietf_enc(uint8_t *c, uint64_t *clen_p, const uint8_t *m, uint64_t mlen, const uint8_t *ad, uint64_t adlen, const uint8_t *nsec, const uint8_t *npub, const uint8_t *k) {
    return crypto_aead_chacha20poly1305_ietf_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k);
}

int CNIOSecurityShims_AEAD_chacha20poly1305_ietf_dec(uint8_t *m, uint64_t *mlen_p, uint8_t *nsec, const uint8_t *c, uint64_t clen, const uint8_t *ad, uint64_t adlen, const uint8_t *npub, const uint8_t *k) {
    return crypto_aead_chacha20poly1305_ietf_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k);
}

int CNIOSecurityShims_AEAD_xchacha20poly1305_ietf_enc(uint8_t *c, uint64_t *clen_p, const uint8_t *m, uint64_t mlen, const uint8_t *ad, uint64_t adlen, const uint8_t *nsec, const uint8_t *npub, const uint8_t *k) {
    return crypto_aead_xchacha20poly1305_ietf_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k);
}

int CNIOSecurityShims_AEAD_xchacha20poly1305_ietf_dec(uint8_t *m, uint64_t *mlen_p, uint8_t *nsec, const uint8_t *c, uint64_t clen, const uint8_t *ad, uint64_t adlen, const uint8_t *npub, const uint8_t *k) {
    return crypto_aead_xchacha20poly1305_ietf_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k);
}

int CNIOSecurityShims_AEAD_aes256gcm_enc(uint8_t *c, uint64_t *clen_p, const uint8_t *m, uint64_t mlen, const uint8_t *ad, uint64_t adlen, const uint8_t *nsec, const uint8_t *npub, const uint8_t *k) {
    return crypto_aead_aes256gcm_encrypt(c, clen_p, mlen, mlen, ad, adlen, nsec, npub, k);
}

int CNIOSecurityShims_AEAD_aes256gcm_dec(uint8_t *m, uint64_t *mlen_p, uint8_t *nsec, const uint8_t *c, uint64_t clen, const uint8_t *ad, uint64_t adlen, const uint8_t *npub, const uint8_t *k) {
    return crypto_aead_aes256gcm_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k);
}
