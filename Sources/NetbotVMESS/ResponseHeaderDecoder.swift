//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if compiler(>=5.1)
@_implementationOnly import CCryptoBoringSSL
#else
import CCryptoBoringSSL
#endif
import Crypto
import Foundation
import Logging
import NetbotCore
import NIOCore
import SHAKE128

final public class ResponseHeaderDecoder: ByteToMessageDecoder {
    
    public typealias InboundOut = ByteBuffer
    
    private let logger: Logger
    
    private let authenticationCode: UInt8
    
    private let symmetricKey: SecureBytes
    
    private let nonce: SecureBytes
    
    private let configuration: Configuration!
    
    private let forceAEADDecoding: Bool
    
    private var response: Response?
    
    public init(logger: Logger, authenticationCode: UInt8, symmetricKey: SecureBytes, nonce: SecureBytes, configuration: Configuration, forceAEADDecoding: Bool = true) {
        let hash: (SecureBytes) -> SecureBytes = {
            var hasher = SHA256()
            hasher.update(data: $0)
            return SecureBytes(hasher.finalize().prefix(16))
        }
        
        self.logger = logger
        self.authenticationCode = authenticationCode
        self.symmetricKey = hash(symmetricKey)
        self.nonce = hash(nonce)
        self.configuration = configuration
        self.forceAEADDecoding = forceAEADDecoding
    }
    
    public func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        guard response == nil else {
            guard let out = buffer.readSlice(length: buffer.readableBytes) else {
                return .needMoreData
            }
            
            context.fireChannelRead(wrapInboundOut(out))
            return .needMoreData
        }
        
        guard let response = try parseHeadPart(context: context, data: &buffer) else {
            return .needMoreData
        }
        
        self.response = response
        
        return .continue
    }
    
    /// Parse VMESS response head part.
    ///
    /// - Parameter data: The data used to parse response head part.
    /// - Returns: Response object contains parsed response head fields.
    private func parseHeadPart(context: ChannelHandlerContext, data: inout ByteBuffer) throws -> Response? {
        // Cursor used to recoverty data.
        // When we had read some bytes but that is not enough to parse as response
        // we need return `.needMoreData` and reset `data.readerIndex` to cursor.
        let cursor = data.readerIndex
        
        if forceAEADDecoding {
            var symmetricKey = KDF16.deriveKey(inputKeyMaterial: .init(data: self.symmetricKey), info: [KDFSaltConstAEADRespHeaderLenKey])
            var nonce = KDF12.deriveKey(inputKeyMaterial: .init(data: self.nonce), info: [KDFSaltConstAEADRespHeaderLenIV]).withUnsafeBytes {
                Array($0)
            }
            
            // 2 byte packet length data and 16 overhead
            let overhead = Algorithm.aes128gcm.overhead
            var readLength = 2 + overhead
            guard data.readableBytes >= readLength else {
                return nil
            }
            
            let d = try AES.GCM.open(.init(combined: nonce + data.readBytes(length: readLength)!), using: symmetricKey)
            assert(d.count == 2)
            let packetLengthSize = d.withUnsafeBytes {
                $0.load(as: UInt16.self).bigEndian
            }
            
            readLength = Int(packetLengthSize) + overhead
            
            guard data.readableBytes >= readLength else {
                data.moveReaderIndex(to: cursor)
                return nil
            }
            
            symmetricKey = KDF16.deriveKey(inputKeyMaterial: .init(data: self.symmetricKey), info: [KDFSaltConstAEADRespHeaderPayloadKey])
            nonce = KDF12.deriveKey(inputKeyMaterial: .init(data: self.nonce), info: [KDFSaltConstAEADRespHeaderPayloadIV]).withUnsafeBytes {
                Array($0)
            }
            
            var headPartData = try AES.GCM.open(.init(combined: nonce + data.readBytes(length: readLength)!), using: symmetricKey)
            assert(headPartData.count >= 4)
            
            guard authenticationCode == headPartData.removeFirst() else {
                // FIXME: FAILED TO VALIDATE RESPONSE
                throw CodingError.payloadTooLarge
            }
            
            let options = StreamOptions.init(rawValue: headPartData.removeFirst())
            
            let commandCode = headPartData.removeFirst()
            
            var response = Response.init(authenticationCode: authenticationCode, options: options, commandCode: commandCode, command: nil, body: nil)
            
            guard commandCode != 0 else {
                return response
            }
            
            if let command = try parseCommand(commandCode: commandCode, data: headPartData) {
                response.command = command
            }
            
            return response
        } else {
            guard data.readableBytes >= 4 else {
                return nil
            }
            
            let symmetricKey = UnsafeMutablePointer<AES_KEY>.allocate(capacity: MemoryLayout<AES_KEY>.size)
            symmetricKey.initialize(to: .init())
            defer {
                symmetricKey.deinitialize(count: MemoryLayout<AES_KEY>.size)
                symmetricKey.deallocate()
            }
            
            try self.symmetricKey.withUnsafeBytes {
                guard CCryptoBoringSSL_AES_set_encrypt_key($0.bindMemory(to: UInt8.self).baseAddress, 128, symmetricKey) == 0 else {
                    throw CryptoKitError.underlyingCoreCryptoError(error: Int32(CCryptoBoringSSL_ERR_get_error()))
                }
            }
            
            var headPartData = Data(repeating: 0, count: 4)
            var outLength: Int32 = 0
            var _nonce = self.nonce
            
            let nonce = _nonce.withUnsafeMutableBytes {
                $0.bindMemory(to: UInt8.self).baseAddress
            }
            
            data.withUnsafeReadableBytes { inPtr in
                headPartData.withUnsafeMutableBytes { outPtr in
                    CCryptoBoringSSL_AES_cfb128_encrypt(
                        inPtr.bindMemory(to: UInt8.self).baseAddress,
                        outPtr.bindMemory(to: UInt8.self).baseAddress,
                        4,
                        symmetricKey,
                        nonce,
                        &outLength, AES_DECRYPT
                    )
                }
            }
            assert(headPartData.count == outLength)
            
            guard authenticationCode == headPartData.removeFirst() else {
                // FIXME: FAILED TO VALIDATE RESPONSE
                throw CodingError.payloadTooLarge
            }
            
            let options = StreamOptions.init(rawValue: headPartData.removeFirst())
            
            let commandCode = headPartData.removeFirst()
            
            var response = Response.init(
                authenticationCode: authenticationCode,
                options: options,
                commandCode: commandCode,
                command: nil,
                body: nil
            )
            
            guard commandCode != 0 else {
                return response
            }
            
            let commandLength = Int(headPartData.removeFirst())
            guard commandLength != 0 else {
                return response
            }
            
            guard data.readableBytes >= commandLength else {
                data.moveReaderIndex(to: cursor)
                return nil
            }
            
            headPartData = Data(repeating: 0, count: commandLength)
            outLength = 0
            data.withUnsafeReadableBytes { inPtr in
                headPartData.withUnsafeMutableBytes { outPtr in
                    CCryptoBoringSSL_AES_cfb128_encrypt(
                        inPtr.bindMemory(to: UInt8.self).baseAddress,
                        outPtr.bindMemory(to: UInt8.self).baseAddress,
                        commandLength,
                        symmetricKey,
                        nonce,
                        &outLength, AES_DECRYPT
                    )
                }
            }
            assert(headPartData.count == outLength)
            
            if let command = try parseCommand(commandCode: commandCode, data: headPartData) {
                response.command = command
            }
            
            return response
        }
    }
    
    /// Parse command with specified commandCode and data.
    /// - Parameters:
    ///   - commandCode: The command code.
    ///   - data: The data contains command details.
    /// - Returns: Parsed response command.
    private func parseCommand(commandCode: UInt8, data: Data) throws -> ResponseCommand? {
        var mutableData = data
        
        let commandLength = Int(mutableData.removeFirst())
        
        guard commandLength != 0 else {
            return nil
        }
        
        guard mutableData.count > 4, mutableData.count >= commandLength else {
            // TODO: Specified Length Error
            throw CodingError.invalidPacketSize
        }
        
        let actualAuthCode = mutableData.prefix(upTo: 4).withUnsafeBytes {
            $0.load(as: UInt32.self).bigEndian
        }
        
        let expectedAuthCode = mutableData[4...].withUnsafeBytes {
            CCryptoBoringSSL_OPENSSL_hash32($0.baseAddress, $0.count)
        }
        
        if actualAuthCode != expectedAuthCode {
            // TODO: Specified Verify Error
            throw CodingError.invalidPacketSize
        }
        
        switch commandCode {
            case 1:
                mutableData = mutableData.dropFirst(4)
                guard !mutableData.isEmpty else {
                    throw CodingError.invalidPacketSize
                }
                
                let addressLength = Int(mutableData.removeFirst())
                guard mutableData.count >= addressLength else {
                    throw CodingError.invalidPacketSize
                }
                
                var address: NetAddress?
                // Parse address
                if addressLength > 0 {
                    address = try parseAddress(data: mutableData.prefix(addressLength))
                    mutableData = mutableData.dropFirst(4)
                }
                
                // Parse port
                guard mutableData.count >= 2 else {
                    throw CodingError.invalidPacketSize
                }
                let port = mutableData.prefix(2).withUnsafeBytes {
                    $0.load(as: in_port_t.self)
                }
                if let v = address {
                    switch v {
                        case .domainPort(let string, _):
                            address = .domainPort(string, Int(port))
                        case .socketAddress(let socketAddress):
                            var socketAddress = socketAddress
                            socketAddress.port = Int(port)
                            address = .socketAddress(socketAddress)
                    }
                }
                mutableData = mutableData.dropFirst(2)
                
                // Parse ID
                guard mutableData.count >= MemoryLayout<UUID>.size else {
                    throw CodingError.invalidPacketSize
                }
                let id = mutableData.prefix(MemoryLayout<UUID>.size).withUnsafeBytes {
                    $0.load(as: UUID.self)
                }
                mutableData = mutableData.dropFirst(MemoryLayout<UUID>.size)
                
                // Parse countOfAlterIDs
                guard mutableData.count >= 2 else {
                    throw CodingError.invalidPacketSize
                }
                let countOfAlterIDs = mutableData.prefix(2).withUnsafeBytes {
                    $0.load(as: UInt16.self).bigEndian
                }
                mutableData = mutableData.dropFirst(2)
                
                // Parse level
                guard mutableData.count >= 2 else {
                    throw CodingError.invalidPacketSize
                }
                let level = mutableData.prefix(2).withUnsafeBytes {
                    UInt32($0.load(as: UInt16.self))
                }
                mutableData = mutableData.dropFirst(2)
                
                // Parse valid time
                guard mutableData.count >= 1 else {
                    throw CodingError.invalidPacketSize
                }
                
                return SwitchAccountCommand.init(
                    id: id,
                    level: level,
                    countOfAlterIDs: countOfAlterIDs,
                    address: address,
                    validMin: mutableData.removeFirst()
                )
            default:
                // TODO: Specified Unsupported Error
                throw CodingError.invalidPacketSize
        }
    }
    
    /// Parse address with specified data.
    /// - Parameter data: The data used to parse address.
    /// - Returns: Parsed address object.
    private func parseAddress(data: Data) throws -> NetAddress {
        guard let string = String(data: data, encoding: .utf8), !string.isEmpty else {
            throw SocketAddressError.unsupported
        }
        
        guard string.isIPAddress() else {
            return .domainPort(string, 0)
        }
        
        return .socketAddress(try .init(ipAddress: string, port: 0))
    }
}
