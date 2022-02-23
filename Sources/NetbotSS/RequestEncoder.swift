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

import Crypto
import Foundation
import Logging
import NIO

public class RequestEncoder: MessageToByteEncoder {
    
    public typealias OutboundIn = ByteBuffer
    
    public var logger: Logger
    public let taskAddress: NetAddress
    public let secretKey: String
    private var symmetricKey: SymmetricKey!
    private var nonce: [UInt8]!
    
    public init(logger: Logger = .init(label: "com.netbot.shadowsocks"), taskAddress: NetAddress, secretKey: String) {
        self.logger = logger
        self.taskAddress = taskAddress
        self.secretKey = secretKey
    }
    
    public func encode(data: ByteBuffer, out: inout ByteBuffer) throws {
        var mutableData = data
        
        var packet = Data()
        
        if symmetricKey == nil {
            let keyByteCount = 32
            let saltByteCount = 32
            let nonceByteCount = 12
            nonce = .init(repeating: 0, count: nonceByteCount)
            let salt = Array<UInt8>(repeating: 0, count: saltByteCount).map({ _ in
                UInt8.random(in: UInt8.min...UInt8.max)
            })
            symmetricKey = hkdfDerivedSymmetricKey(secretKey: secretKey, salt: salt, outputByteCount: keyByteCount)
            
            packet.applying(taskAddress)
            packet = try seal(packet, using: symmetricKey)
            // TCP packet start with fix size salt so insert salt at startIndex.
            packet.insert(contentsOf: salt, at: packet.startIndex)
        }
        
        // Payload length is a 2-byte big-endian unsigned integer capped at 0x3FFF.
        let maxLength = UInt16(mutableData.readableBytes & 0x3FFF)
        let payload = try seal(mutableData.readBytes(length: Int(maxLength))!, using: symmetricKey)
        
        packet.append(payload)
        
        out.writeBytes(packet)
    }
    
    ///  Encrypt plaintext to struct like `[encrypted payload length][length tag][encrypted payload][payload tag]`
    /// - Parameter message: the plaintext waiting to encrypt which confirm to `DataProtocol`
    /// - Returns: encrypted data
    /// - seealso: http://shadowsocks.org/en/wiki/AEAD-Ciphers.html for more information.
    private func seal<Plaintext>(_ message: Plaintext, using symmetricKey: SymmetricKey) throws -> Data where Plaintext: DataProtocol {
        var packet = Data()
        
        var sequence = withUnsafeBytes(of: UInt16(message.count).bigEndian) {
            Array($0)
        }
        var sealedBox = try ChaChaPoly.seal(sequence, using: symmetricKey, nonce: .init(data: nonce))
        packet.append(sealedBox.ciphertext)
        packet.append(sealedBox.tag)
        
        nonce.increment(nonce.count)
        
        sequence = Array(message)
        sealedBox = try ChaChaPoly.seal(sequence, using: symmetricKey, nonce: .init(data: nonce))
        packet.append(sealedBox.ciphertext)
        packet.append(sealedBox.tag)
        
        nonce.increment(nonce.count)
        return packet
    }
}
