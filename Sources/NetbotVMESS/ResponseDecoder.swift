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
import NetbotCore
import NIOCore
import SHAKE128

final public class ResponseDeocoder: ByteToMessageDecoder {
    
    public typealias InboundOut = ByteBuffer
    
    public let logger: Logger
    
    public let session: Session
    
    private let symmetricKey: [UInt8]
    
    private let nonce: [UInt8]
    
    private let configuration: Configuration!
    
    private var response: Response?
    
    private var packetIndex: UInt16 = 0
    
    /// The packet length and padding record.
    private var size: (UInt16, Int)?
    
    private lazy var shake128: SHAKE128? = {
        guard configuration.options.contains(.masking) else {
            return nil
        }
        
        var shake128 = SHAKE128()
        shake128.update(data: nonce)
        return shake128
    }()
    
    public init(logger: Logger, session: Session, configuraiton: Configuration) {
        self.logger = logger
        self.session = session
        self.configuration = configuraiton
        
        let hash: (ArraySlice<UInt8>) -> [UInt8] = {
            var hasher = SHA256()
            hasher.update(data: $0)
            return Array(hasher.finalize().prefix(16))
        }
        
        self.symmetricKey = hash(session.sharedSecretBytes.prefix(16))
        self.nonce = hash(session.sharedSecretBytes[16..<32])
    }
    
    public func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        if response == nil {
            return try parseHeadPart(context: context, data: &buffer)
        }
        
        return try parseBodyPart(context: context, data: &buffer)
    }
    
    /// Parse VMESS response head part.
    ///
    /// - Parameter data: The data used to parse response head part.
    /// - Returns: Response object contains parsed response head fields.
    private func parseHeadPart(context: ChannelHandlerContext, data: inout ByteBuffer) throws -> DecodingState {
        // Cursor used to recoverty data.
        // When we had read some bytes but that is not enough to parse as response
        // we need return `.needMoreData` and reset `data.readerIndex` to cursor.
        let cursor = data.readerIndex
        
        if session.isAEAD {
            var symmetricKey = KDF16.deriveKey(inputKeyMaterial: .init(data: self.symmetricKey), info: [KDFSaltConstAEADRespHeaderLenKey])
            var nonce = KDF12.deriveKey(inputKeyMaterial: .init(data: self.nonce), info: [KDFSaltConstAEADRespHeaderLenIV]).withUnsafeBytes {
                Array($0)
            }
            
            // 2 byte packet length data and 16 overhead
            let overhead = Algorithm.aes128gcm.overhead
            var readLength = 2 + overhead
            guard data.readableBytes >= readLength else {
                return .needMoreData
            }
            
            let d = try AES.GCM.open(.init(combined: nonce + data.readBytes(length: readLength)!), using: symmetricKey)
            assert(d.count == 2)
            let packetLengthSize = d.withUnsafeBytes {
                $0.load(as: UInt16.self).bigEndian
            }
            
            readLength = Int(packetLengthSize) + overhead
            
            guard data.readableBytes >= readLength else {
                data.moveReaderIndex(to: cursor)
                return .needMoreData
            }
            
            symmetricKey = KDF16.deriveKey(inputKeyMaterial: .init(data: self.symmetricKey), info: [KDFSaltConstAEADRespHeaderPayloadKey])
            nonce = KDF12.deriveKey(inputKeyMaterial: .init(data: self.nonce), info: [KDFSaltConstAEADRespHeaderPayloadIV]).withUnsafeBytes {
                Array($0)
            }
            
            var headPartData = try AES.GCM.open(.init(combined: nonce + data.readBytes(length: readLength)!), using: symmetricKey)
            assert(headPartData.count >= 4)
            
            let authenticationCode = headPartData.removeFirst()
            guard authenticationCode == session.sharedSecretBytes.last else {
                // FIXME: FAILED TO VALIDATE RESPONSE
                throw CodingError.payloadTooLarge
            }
            
            let options = StreamOptions.init(rawValue: headPartData.removeFirst())
            
            let commandCode = headPartData.removeFirst()
            
            response = .init(authenticationCode: authenticationCode, options: options, commandCode: commandCode, command: nil, body: nil)
            
            guard commandCode != 0 else {
                return .continue
            }
            
            if let command = try parseCommand(commandCode: commandCode, data: headPartData) {
                response?.command = command
            }
            
            return .continue
        } else {
            guard data.readableBytes >= 4 else {
                return .needMoreData
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
            let nonce = _nonce.withUnsafeMutableBufferPointer {
                $0.baseAddress
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
            
            let authenticationCode = headPartData.removeFirst()
            guard authenticationCode == session.sharedSecretBytes.last else {
                // FIXME: FAILED TO VALIDATE RESPONSE
                throw CodingError.payloadTooLarge
            }
            
            let options = StreamOptions.init(rawValue: headPartData.removeFirst())
            
            let commandCode = headPartData.removeFirst()
            
            response = .init(
                authenticationCode: authenticationCode,
                options: options,
                commandCode: commandCode,
                command: nil,
                body: nil
            )
            
            guard commandCode != 0 else {
                return .continue
            }
            
            let commandLength = Int(headPartData.removeFirst())
            guard commandLength != 0 else {
                return .continue
            }
            
            guard data.readableBytes >= commandLength else {
                data.moveReaderIndex(to: cursor)
                return .needMoreData
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
                response?.command = command
            }
            
            return .continue
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
        
        guard string.isIPAddr() else {
            return .domainPort(string, 0)
        }
        
        return .socketAddress(try .init(ipAddress: string, port: 0))
    }
    
    /// Parse response body with specified response and data.
    ///
    /// *Return nil to wait for more bytes.*
    /// - Parameters:
    ///   - response: The response contains head fields.
    ///   - data: The data used to parse response body.
    /// - Returns: Parsed response object.
    private func parseBodyPart(context: ChannelHandlerContext, data: inout ByteBuffer) throws -> DecodingState {
        switch configuration.algorithm {
            case .none:
                // TODO: None Security Support
                fatalError()
            case .aes128cfb:
                // TODO: Legacy Security Support
                fatalError()
            case .aes128gcm, .chacha20poly1305:
                // TCP
                let overhead = configuration.algorithm.overhead
                
                let nonce = withUnsafeBytes(of: packetIndex.bigEndian) {
                    Array($0) + self.nonce[2..<12]
                }
                
                var size: (packetLength: UInt16, padding: Int)
                
                if self.size == nil {
                    guard let parsedSize = try parsePacketLength(data: &data, nonce: nonce) else {
                        return .needMoreData
                    }
                    
                    self.size = parsedSize
                }
                
                assert(self.size != nil, "Illegal size should not be nil")
                size = self.size!
                
                guard data.readableBytes >= Int(size.packetLength) else {
                    return .needMoreData
                }
                
                // Remove random padding bytes.
                let combined = nonce + data.readBytes(length: Int(size.packetLength))!.dropLast(size.padding)
                
                var packet: Data
                if configuration.algorithm == .aes128gcm {
                    packet = try AES.GCM.open(.init(combined: combined), using: .init(data: symmetricKey))
                } else {
                    let symmetricKey = generateChaChaPolySymmetricKey(inputKeyMaterial: symmetricKey)
                    packet = try ChaChaPoly.open(.init(combined: combined), using: symmetricKey)
                }
                
                assert(response != nil)
                if response?.body != nil {
                    response?.body?.writeBytes(packet)
                } else {
                    response?.body = context.channel.allocator.buffer(bytes: packet)
                }
                
                packetIndex += 1
                self.size = nil
                
                context.fireChannelRead(wrapInboundOut(ByteBuffer(bytes: packet)))
                
                guard size.packetLength == overhead + size.padding else {
                    return .continue
                }
                
                return parseEndPart(context: context)
            default:
                fatalError("Unsupported security")
        }
    }
    
    private func parsePacketLength(data: inout ByteBuffer, nonce: [UInt8]) throws -> (UInt16, Int)? {
        let overhead = configuration.algorithm.overhead
        
        let packetLength = configuration.options.contains(.authenticatedLength) ? 2 + overhead : 2
        
        guard data.readableBytes >= packetLength else {
            return nil
        }
        
        let packetLengthData = data.readBytes(length: packetLength)!
        
        var padding = 0
        if configuration.options.shouldPadding {
            assert(shake128 != nil)
            shake128!.read(digestSize: 2).withUnsafeBytes {
                padding = Int($0.load(as: UInt16.self).bigEndian % 64)
            }
        }
        
        guard configuration.options.contains(.authenticatedLength) else {
            guard configuration.options.contains(.masking) else {
                return packetLengthData.withUnsafeBytes {
                    ($0.load(as: UInt16.self), padding)
                }
            }
            
            assert(shake128 != nil)
            return shake128!.read(digestSize: 2).withUnsafeBytes {
                let mask = $0.load(as: UInt16.self).bigEndian
                
                return packetLengthData.withUnsafeBytes {
                    (mask ^ $0.load(as: UInt16.self).bigEndian, padding)
                }
            }
        }
        
        var symmetricKey = KDF16.deriveKey(inputKeyMaterial: .init(data: symmetricKey), info: ["auth_len".data(using: .utf8)!])
        
        if configuration.algorithm == .aes128gcm {
            let sealedBox = try AES.GCM.SealedBox.init(combined: nonce + packetLengthData)
            return try AES.GCM.open(sealedBox, using: symmetricKey).withUnsafeBytes {
                ($0.load(as: UInt16.self).bigEndian + UInt16(overhead), padding)
            }
        } else {
            symmetricKey = symmetricKey.withUnsafeBytes {
                generateChaChaPolySymmetricKey(inputKeyMaterial: $0)
            }
            let sealedBox = try ChaChaPoly.SealedBox.init(combined: nonce + packetLengthData)
            return try ChaChaPoly.open(sealedBox, using: symmetricKey).withUnsafeBytes {
                ($0.load(as: UInt16.self).bigEndian + UInt16(overhead), padding)
            }
        }
    }
    
    private func parseEndPart(context: ChannelHandlerContext) -> DecodingState {
        //        if let response = response?.body {
        //            context.fireChannelRead(wrapInboundOut(response))
        //        } else {
        //            context.fireChannelRead(wrapInboundOut(context.channel.allocator.buffer(capacity: 0)))
        //        }
        print("EOF")
        // Restore state to initial.
        response = nil
        packetIndex = 0
        size = nil
        
        guard configuration.options.contains(.masking) else {
            return .continue
        }
        
        shake128 = .init()
        shake128?.update(data: nonce)
        
        return .continue
    }
}
