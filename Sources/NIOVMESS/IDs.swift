//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation

let KDFSaltConstAuthIDEncryptionKey = "AES Auth ID Encryption".data(using: .utf8)!
let KDFSaltConstAEADRespHeaderLenKey = "AEAD Resp Header Len Key".data(using: .utf8)!
let KDFSaltConstAEADRespHeaderLenIV = "AEAD Resp Header Len IV".data(using: .utf8)!
let KDFSaltConstAEADRespHeaderPayloadKey = "AEAD Resp Header Key".data(using: .utf8)!
let KDFSaltConstAEADRespHeaderPayloadIV = "AEAD Resp Header IV".data(using: .utf8)!
let KDFSaltConstVMessAEADKDF = "VMess AEAD KDF".data(using: .utf8)!
let KDFSaltConstVMessHeaderPayloadAEADKey = "VMess Header AEAD Key".data(using: .utf8)!
let KDFSaltConstVMessHeaderPayloadAEADIV = "VMess Header AEAD Nonce".data(using: .utf8)!
let KDFSaltConstVMessHeaderPayloadLengthAEADKey = "VMess Header AEAD Key_Length".data(using: .utf8)!
let KDFSaltConstVMessHeaderPayloadLengthAEADIV = "VMess Header AEAD Nonce_Length".data(
    using: .utf8
)!
