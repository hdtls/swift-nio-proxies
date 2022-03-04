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
import NIOCore

///
/// Spec: http://shadowsocks.org/en/wiki/AEAD-Ciphers.html
///
/// TCP
///
/// An AEAD encrypted TCP stream starts with a randomly generated salt to derive the per-session subkey, followed by any
/// number of encrypted chunks. Each chunk has the following structure:
///
///      [encrypted payload length][length tag][encrypted payload][payload tag]
///
/// Payload length is a 2-byte big-endian unsigned integer capped at 0x3FFF. The higher two bits are reserved and must be
/// set to zero. Payload is therefore limited to 16*1024 - 1 bytes.
///
/// The first AEAD encrypt/decrypt operation uses a counting nonce starting from 0. After each encrypt/decrypt operation,
/// the nonce is incremented by one as if it were an unsigned little-endian integer. Note that each TCP chunk involves
/// two AEAD encrypt/decrypt operation: one for the payload length, and one for the payload. Therefore each chunk
/// increases the nonce twice.
///
/// UDP
///
/// An AEAD encrypted UDP packet has the following structure:
///
///      [salt][encrypted payload][tag]
///
/// The salt is used to derive the per-session subkey and must be generated randomly to ensure uniqueness. Each UDP
/// packet is encrypted/decrypted i`ndependently, using the derived subkey and a nonce with all zero bytes.
///
///

public class ResponseDecoder: ByteToMessageDecoder {
    
    public typealias InboundOut = ByteBuffer
    
    public let secretKey: String
    
    private var symmetricKey: SymmetricKey!
    
    private var nonce: [UInt8]
    
    public init(secretKey: String) {
        self.secretKey = secretKey
        self.nonce = .init(repeating: 0, count: 12)
    }
    
    public func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        if symmetricKey == nil {
            let saltByteCount = 32
            let keyByteCount = 32
            guard buffer.readableBytes >= saltByteCount else {
                return .needMoreData
            }
            let salt = buffer.readBytes(length: saltByteCount)!
            symmetricKey = hkdfDerivedSymmetricKey(secretKey: secretKey, salt: salt, outputByteCount: keyByteCount)
        }
        
        let tagByteCount = 16
        let trunkSize = 2
        
        var copyLength = trunkSize + tagByteCount
        
        guard buffer.readableBytes > copyLength else {
            return .needMoreData
        }
        
        var combined = nonce + buffer.readBytes(length: copyLength)!
        var sealedBox = try ChaChaPoly.SealedBox.init(combined: combined)
        var bytes = try ChaChaPoly.open(sealedBox, using: symmetricKey)
        
        copyLength = bytes.withUnsafeBytes {
            Int($0.bindMemory(to: UInt16.self).baseAddress!.pointee.bigEndian) + tagByteCount
        }
        
        guard buffer.readableBytes >= copyLength else {
            buffer.moveReaderIndex(to: buffer.readerIndex - trunkSize - tagByteCount)
            return .needMoreData
        }
        
        nonce.increment(nonce.count)
        
        combined = nonce + buffer.readBytes(length: copyLength)!
        sealedBox = try ChaChaPoly.SealedBox.init(combined: combined)
        bytes = try ChaChaPoly.open(sealedBox, using: symmetricKey)
        
        nonce.increment(nonce.count)
        
        context.fireChannelRead(wrapInboundOut(ByteBuffer(bytes: bytes)))
        
        return .continue
    }
    
}

enum Packet {
    case address(NetAddress)
    case buffer(ByteBuffer)
}

public class RequestDecoder: ByteToMessageDecoder {
    
    public typealias InboundOut = ByteBuffer
    
    public let secretKey: String
    
    private var symmetricKey: SymmetricKey!
    
    private var nonce: [UInt8]
    
    public init(secretKey: String) {
        self.secretKey = secretKey
        self.nonce = .init(repeating: 0, count: 12)
    }
    
    public func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        var symmetricKey = symmetricKey
        if symmetricKey == nil {
            let saltByteCount = 32
            let keyByteCount = 32
            guard buffer.readableBytes >= saltByteCount else {
                return .needMoreData
            }
            let salt = buffer.readBytes(length: saltByteCount)!
            symmetricKey = hkdfDerivedSymmetricKey(secretKey: secretKey, salt: salt, outputByteCount: keyByteCount)
        }
        
        let tagByteCount = 16
        let trunkSize = 2
        
        var copyLength = trunkSize + tagByteCount
        
        guard buffer.readableBytes > copyLength else {
            return .needMoreData
        }
        
        var combined = nonce + buffer.readBytes(length: copyLength)!
        var sealedBox = try ChaChaPoly.SealedBox.init(combined: combined)
        var bytes = try ChaChaPoly.open(sealedBox, using: symmetricKey!)
        copyLength = bytes.withUnsafeBytes {
            Int($0.bindMemory(to: UInt16.self).baseAddress!.pointee.bigEndian) + tagByteCount
        }
        
        guard buffer.readableBytes >= copyLength else {
            buffer.moveReaderIndex(to: buffer.readerIndex - trunkSize - tagByteCount)
            return .needMoreData
        }
        
        nonce.increment(nonce.count)
        
        combined = nonce + buffer.readBytes(length: copyLength)!
        sealedBox = try ChaChaPoly.SealedBox.init(combined: combined)
        bytes = try ChaChaPoly.open(sealedBox, using: symmetricKey!)
        
        nonce.increment(nonce.count)
        
        if self.symmetricKey == nil {
            self.symmetricKey = symmetricKey
            context.fireChannelRead(NIOAny(Packet.address(try! bytes.readAddressIfPossible()!)))
        } else {
            context.fireChannelRead(NIOAny(Packet.buffer(ByteBuffer(bytes: bytes))))
        }
        return .needMoreData
    }
    
}
