//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation

/// Shadowsocks crypto algorithm.
///
/// We don't care about rawValue is uppercase or lowercase for example:
///     CryptoAlgorithm(rawValue: "aes-128-gcm") == CryptoAlgorithm(rawValue: "AES-128-GCM") // true
public enum CryptoAlgorithm: String, CaseIterable, Equatable {
    
    case aes128Gcm = "AES-128-GCM"
    case chaCha20Poly1305 = "ChaCha20-Poly1305"
    
    public init?(rawValue: String) {
        switch rawValue.uppercased() {
            case CryptoAlgorithm.aes128Gcm.rawValue:
                self = .aes128Gcm
            case CryptoAlgorithm.chaCha20Poly1305.rawValue.uppercased():
                self = .chaCha20Poly1305
            default:
                return nil
        }
    }
}


public protocol ConfigurationProtocol {
    
    var algorithm: CryptoAlgorithm { get }
    
    var passwordReference: String { get }
}
