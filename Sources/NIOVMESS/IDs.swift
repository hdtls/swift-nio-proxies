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

let kDFSaltConstAuthIDEncryptionKey = "AES Auth ID Encryption".data(using: .utf8)!
let kDFSaltConstAEADRespHeaderLenKey = "AEAD Resp Header Len Key".data(using: .utf8)!
let kDFSaltConstAEADRespHeaderLenIV = "AEAD Resp Header Len IV".data(using: .utf8)!
let kDFSaltConstAEADRespHeaderPayloadKey = "AEAD Resp Header Key".data(using: .utf8)!
let kDFSaltConstAEADRespHeaderPayloadIV = "AEAD Resp Header IV".data(using: .utf8)!
let kDFSaltConstVMessAEADKDF = "VMess AEAD KDF".data(using: .utf8)!
let kDFSaltConstVMessHeaderPayloadAEADKey = "VMess Header AEAD Key".data(using: .utf8)!
let kDFSaltConstVMessHeaderPayloadAEADIV = "VMess Header AEAD Nonce".data(using: .utf8)!
let kDFSaltConstVMessHeaderPayloadLengthAEADKey = "VMess Header AEAD Key_Length".data(using: .utf8)!
let kDFSaltConstVMessHeaderPayloadLengthAEADIV = "VMess Header AEAD Nonce_Length".data(
    using: .utf8
)!
