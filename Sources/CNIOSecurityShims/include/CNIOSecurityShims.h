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

#ifndef C_NIO_SECURITY_SHIMS_h
#define C_NIO_SECURITY_SHIMS_h

#include <stdint.h>

int8_t CNIOSecurityShims_SECURITY_init(void);

void CNIOSecurityShims_SECURITY_INCREMENT(uint8_t *n, size_t nlen);

int8_t CNIOSecurityShims_STREAM_salsa20(uint8_t *c, const uint8_t *m, uint64_t mlen, const uint8_t *n, uint64_t ic, const uint8_t *k);

int8_t CNIOSecurityShims_STREAM_chacha20(uint8_t *c, const uint8_t *m, uint64_t mlen, const uint8_t *n, uint64_t ic, const uint8_t *k);

int8_t CNIOSecurityShims_STREAM_chacha20_ietf(uint8_t *c, const uint8_t *m, uint64_t mlen, const uint8_t *n, uint64_t ic, const uint8_t *k);

int8_t CNIOSecurityShims_STREAM_xchacha20(uint8_t *c, const uint8_t *m, uint64_t mlen, const uint8_t *n, uint64_t ic, const uint8_t *k);

int8_t CNIOSecurityShims_AEAD_chacha20poly1305_enc(uint8_t *c, uint64_t *clen_p, const uint8_t *m, uint64_t mlen, const uint8_t *ad, uint64_t adlen, const uint8_t *nsec, const uint8_t *npub, const uint8_t *k);

int8_t CNIOSecurityShims_AEAD_chacha20poly1305_dec(uint8_t *m, uint64_t *mlen_p, uint8_t *nsec, const uint8_t *c, uint64_t clen, const uint8_t *ad, uint64_t adlen, const uint8_t *npub, const uint8_t *k);

int8_t CNIOSecurityShims_AEAD_chacha20poly1305_ietf_enc(uint8_t *c, uint64_t *clen_p, const uint8_t *m, uint64_t mlen, const uint8_t *ad, uint64_t adlen, const uint8_t *nsec, const uint8_t *npub, const uint8_t *k);

int8_t CNIOSecurityShims_AEAD_chacha20poly1305_ietf_dec(uint8_t *m, uint64_t *mlen_p, uint8_t *nsec, const uint8_t *c, uint64_t clen, const uint8_t *ad, uint64_t adlen, const uint8_t *npub, const uint8_t *k);

int8_t CNIOSecurityShims_AEAD_xchacha20poly1305_ietf_enc(uint8_t *c, uint64_t *clen_p, const uint8_t *m, uint64_t mlen, const uint8_t *ad, uint64_t adlen, const uint8_t *nsec, const uint8_t *npub, const uint8_t *k);

int8_t CNIOSecurityShims_AEAD_xchacha20poly1305_ietf_dec(uint8_t *m, uint64_t *mlen_p, uint8_t *nsec, const uint8_t *c, uint64_t clen, const uint8_t *ad, uint64_t adlen, const uint8_t *npub, const uint8_t *k);

int8_t CNIOSecurityShims_AEAD_aes256gcm_enc(uint8_t *c, uint64_t *clen_p, const uint8_t *m, uint64_t mlen, const uint8_t *ad, uint64_t adlen, const uint8_t *nsec, const uint8_t *npub, const uint8_t *k);

int8_t CNIOSecurityShims_AEAD_aes256gcm_dec(uint8_t *m, uint64_t *mlen_p, uint8_t *nsec, const uint8_t *c, uint64_t clen, const uint8_t *ad, uint64_t adlen, const uint8_t *npub, const uint8_t *k);

#endif /* C_NIO_SECURITY_SHIMS_h */
