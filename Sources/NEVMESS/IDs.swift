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

let kDFSaltConstAuthIDEncryptionKey = Data("AES Auth ID Encryption".utf8)
let kDFSaltConstAEADRespHeaderLenKey = Data("AEAD Resp Header Len Key".utf8)
let kDFSaltConstAEADRespHeaderLenIV = Data("AEAD Resp Header Len IV".utf8)
let kDFSaltConstAEADRespHeaderPayloadKey = Data("AEAD Resp Header Key".utf8)
let kDFSaltConstAEADRespHeaderPayloadIV = Data("AEAD Resp Header IV".utf8)
let kDFSaltConstVMessAEADKDF = Data("VMess AEAD KDF".utf8)
let kDFSaltConstVMessHeaderPayloadAEADKey = Data("VMess Header AEAD Key".utf8)
let kDFSaltConstVMessHeaderPayloadAEADIV = Data("VMess Header AEAD Nonce".utf8)
let kDFSaltConstVMessHeaderPayloadLengthAEADKey = Data("VMess Header AEAD Key_Length".utf8)
let kDFSaltConstVMessHeaderPayloadLengthAEADIV = Data("VMess Header AEAD Nonce_Length".utf8)
