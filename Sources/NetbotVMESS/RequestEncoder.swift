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
import NIO
import SHAKE128

public final class RequestEncoder: MessageToByteEncoder {
    
    public typealias OutboundIn = ByteBuffer
    
    private let id: UUID
    
    public let logger: Logger
    
    private var requestHead: VMESSRequestHead
    
    private var packetIndex: UInt16 = 0
    
    struct Session {
        var isAEAD: Bool
        var symmetricKey: [UInt8]
        var nonce: [UInt8]
        var symmetricKey2: [UInt8]
        var nonce2: [UInt8]
        var responseHeader: UInt8
        
        init(isAEAD: Bool) {
            let securityBytes = Array<UInt8>(capacity: 33)
            
            symmetricKey = Array(securityBytes.prefix(16))
            nonce = Array(securityBytes[16..<32])
            responseHeader = securityBytes.last!
            self.isAEAD = isAEAD
            
            if isAEAD {
                symmetricKey2 = symmetricKey.withUnsafeBytes {
                    var sha256 = SHA256()
                    sha256.update(bufferPointer: $0)
                    return sha256.finalize().withUnsafeBytes {
                        Array($0.prefix(16))
                    }
                }
                
                nonce2 = nonce.withUnsafeBytes {
                    var sha256 = SHA256()
                    sha256.update(bufferPointer: $0)
                    return sha256.finalize().withUnsafeBytes {
                        Array($0.prefix(16))
                    }
                }
            } else {
                symmetricKey2 = symmetricKey.withUnsafeBytes {
                    var md5 = Insecure.MD5()
                    md5.update(bufferPointer: $0)
                    return md5.finalize().withUnsafeBytes {
                        Array($0)
                    }
                }
                
                nonce2 = nonce.withUnsafeBytes {
                    var sha256 = SHA256()
                    sha256.update(bufferPointer: $0)
                    return sha256.finalize().withUnsafeBytes {
                        Array($0)
                    }
                }
            }
        }
    }
    
    private var session: Session
    
    public init(logger: Logger, taskAddress: NetAddress, id: UUID) {
        
        self.logger = logger
        self.id = id
        
        var algorithm: Algorithm = .aes128gcm
        
        var options: Options = .chunkStream
        let account = Account(id: .init(), alterIDs: [], security: algorithm)
        
        if algorithm == .aes128gcm || algorithm == .none || algorithm == .chacha20poly1305 {
            options.insert(.chunkMasking)
        }
        
        if algorithm.shouldEnablePadding && options.contains(.chunkMasking) {
            options.insert(.globalPadding)
        }
        
        if algorithm == .zero {
            algorithm = .none
            options.remove(.chunkStream)
            options.remove(.chunkMasking)
        }
        
        if account.authenticatedLengthExperiment {
            options.insert(.authenticatedLength)
        }
        
        session = .init(isAEAD: true)
        
        self.requestHead = .init(version: .v1, command: .tcp, options: options, algorithm: algorithm, address: taskAddress)
    }
    
    public func encode(data: ByteBuffer, out: inout ByteBuffer) throws {
        let headPart = try prepareHeadPart()
        print(Array(headPart))
        out.writeBytes(headPart)
        out.writeBytes(try prepareBodyPart(data: data))
        out.writeBytes(try prepareEndPart())
    }
    
    /// Prepare HEAD part data for request.
    ///
    /// If use AEAD to encrypt request then the HEAD part only contains instruction else HEAD part contains
    /// authentication info and instruction two parts.
    /// - Returns: Encrypted HEAD part data.
    private func prepareHeadPart() throws -> Data {
        let date = Date() + TimeInterval.random(in: -30...30)
        let timestamp = UInt64(date.timeIntervalSince1970)
        
        var result = Data()
        result += try prepareCertificationInfoPart(timestamp: timestamp)
        result += try prepareInstructionPart(timestamp: timestamp)
        return result
    }
    
    /// Prepare HEAD certification part data with specified timestamp.
    ///
    /// If use AEAD to encrypt request just return empty data instead.
    /// - Parameter timestamp: UTC UInt64 timestamp.
    /// - Returns: Encrypted certification part data.
    private func prepareCertificationInfoPart(timestamp: UInt64) throws -> Data {
        guard !session.isAEAD else {
            return .init()
        }
        
        // TODO: Random Alter IDs
        return withUnsafeBytes(of: id) {
            var hasher = HMAC<Insecure.MD5>(key: .init(data: $0))
            return withUnsafeBytes(of: timestamp.bigEndian) {
                hasher.update(data: $0)
                return hasher.finalize().withUnsafeBytes {
                    Data($0)
                }
            }
        }
    }
    
    /// Prepare HEAD instruction part data with specified timestamp.
    /// - Parameter timestamp: UTC UInt64 timestamp.
    /// - Returns: Encrypted instruction part data.
    private func prepareInstructionPart(timestamp: UInt64) throws -> Data {
        var buffer = ByteBuffer()
        buffer.writeInteger(ProtocolVersion.v1.rawValue)
        buffer.writeBytes(session.nonce)
        buffer.writeBytes(session.symmetricKey)
        buffer.writeInteger(session.responseHeader)
        buffer.writeInteger(requestHead.options.rawValue)
        
        let padding = UInt8.random(in: 0...16)
        buffer.writeInteger((padding << 4) | requestHead.algorithm.rawValue)
        // Write zero as keeper.
        buffer.writeInteger(UInt8(0))
        buffer.writeInteger(requestHead.command.rawValue)
        
        if requestHead.command != .mux {
            buffer.writeAddress(requestHead.address)
        }
        
        if padding > 0 {
            buffer.writeBytes(Array<UInt8>(capacity: Int(padding)))
        }
        
        buffer.writeInteger(buffer.withUnsafeReadableBytes {
            CCryptoBoringSSL_OPENSSL_hash32($0.baseAddress, $0.count)
        })
        
        let inputKeyMaterial = generateCmdKey(id)
        if session.isAEAD {
            let authenticatedData = try generateAuthenticatedData(inputKeyMaterial)
            let randomPath = Array<UInt8>.init(capacity: 8)
            
            var info = [
                [],
                authenticatedData,
                randomPath
            ]
            
            let sealedLengthBox: AES.GCM.SealedBox = try withUnsafeBytes(of: UInt16(buffer.readableBytes).bigEndian) {
                info[0] = Array(KDFSaltConstVMessHeaderPayloadLengthAEADKey)
                let symmetricKey = KDF16.deriveKey(inputKeyMaterial: inputKeyMaterial, info: info)
                
                info[0] = Array(KDFSaltConstVMessHeaderPayloadLengthAEADIV)
                let nonce = try KDF12.deriveKey(inputKeyMaterial: inputKeyMaterial, info: info).withUnsafeBytes { ptr in
                    try AES.GCM.Nonce.init(data: ptr)
                }
                return try AES.GCM.seal($0, using: symmetricKey, nonce: nonce, authenticating: authenticatedData)
            }
            
            let sealedPayloadBox: AES.GCM.SealedBox = try buffer.withUnsafeReadableBytes {
                info[0] = Array(KDFSaltConstVMessHeaderPayloadAEADKey)
                let symmetricKey = KDF16.deriveKey(inputKeyMaterial: inputKeyMaterial, info: info)
                
                info[0] = Array(KDFSaltConstVMessHeaderPayloadAEADIV)
                let nonce = try KDF12.deriveKey(inputKeyMaterial: inputKeyMaterial, info: info).withUnsafeBytes { ptr in
                    try AES.GCM.Nonce.init(data: ptr)
                }
                return try AES.GCM.seal($0, using: symmetricKey, nonce: nonce, authenticating: authenticatedData)
            }
            
            return authenticatedData
            + sealedLengthBox.ciphertext
            + sealedLengthBox.tag
            + randomPath
            + sealedPayloadBox.ciphertext
            + sealedPayloadBox.tag
        } else {
            // Hash timestamp original impl of go see `client.go hashTimestamp` in v2flay.
            var hasher = Insecure.MD5.init()
            withUnsafeBytes(of: timestamp.bigEndian) {
                for _ in 0..<4 {
                    hasher.update(bufferPointer: $0)
                }
            }
            
            let symmetricKey = UnsafeMutablePointer<AES_KEY>.allocate(capacity: MemoryLayout<AES_KEY>.size)
            symmetricKey.initialize(to: .init())
            defer {
                symmetricKey.deinitialize(count: MemoryLayout<AES_KEY>.size)
                symmetricKey.deallocate()
            }
            
            inputKeyMaterial.withUnsafeBytes {
                _ = CCryptoBoringSSL_AES_set_encrypt_key($0.bindMemory(to: UInt8.self).baseAddress, 128, symmetricKey)
            }
            
            var l: Int32 = 0
            var result = Array<UInt8>.init(repeating: 0, count: buffer.readableBytes)
            result.withUnsafeMutableBufferPointer { outPtr in
                buffer.withUnsafeReadableBytes { inPtr in
                    hasher.finalize().withUnsafeBytes { ivPtr in
                        CCryptoBoringSSL_AES_cfb128_encrypt(
                            inPtr.bindMemory(to: UInt8.self).baseAddress,
                            outPtr.baseAddress,
                            inPtr.count,
                            symmetricKey,
                            UnsafeMutablePointer(mutating: ivPtr.bindMemory(to: UInt8.self).baseAddress),
                            &l,
                            AES_ENCRYPT
                        )
                    }
                }
            }
            return Data(result)
        }
    }
    
    /// Generate authenticated data with specified key.
    /// - Parameter key: Input key material.
    /// - Returns: Encrypted authenticated data bytes.
    private func generateAuthenticatedData(_ key: SymmetricKey) throws -> [UInt8] {
        var byteBuffer = withUnsafeBytes(of: UInt64(Date().timeIntervalSince1970).bigEndian, Array.init)
        byteBuffer += Array<UInt8>.init(capacity: 4)
        byteBuffer += withUnsafeBytes(of: CRC32.checksum(byteBuffer).bigEndian, Array.init)
        
        let inputKeyMaterial = KDF16.deriveKey(
            inputKeyMaterial: key,
            info: [Array(KDFSaltConstAuthIDEncryptionKey)]
        )
        
        let symmetricKey = UnsafeMutablePointer<AES_KEY>.allocate(capacity: MemoryLayout<AES_KEY>.size)
        symmetricKey.initialize(to: .init())
        defer {
            symmetricKey.deinitialize(count: MemoryLayout<AES_KEY>.size)
            symmetricKey.deallocate()
        }
        
        try inputKeyMaterial.withUnsafeBytes {
            guard CCryptoBoringSSL_AES_set_encrypt_key($0.bindMemory(to: UInt8.self).baseAddress, 128, symmetricKey) == 0 else {
                throw CryptoKitError.incorrectKeySize
            }
        }
        
        var result = Array<UInt8>.init(repeating: 0, count: 16)
        
        byteBuffer.withUnsafeBufferPointer { inPtr in
            result.withUnsafeMutableBufferPointer { outPtr in
                CCryptoBoringSSL_AES_encrypt(inPtr.baseAddress, outPtr.baseAddress, symmetricKey)
            }
        }
        
        return result
    }
    
    /// Prepare Body part data with specified data.
    /// - Parameter data: Original body data.
    /// - Returns: Encrypted body part data.
    private func prepareBodyPart(data: ByteBuffer) throws -> Data {
        var mutableData = data
        
        var byteBuffer = ByteBuffer()
        
        switch requestHead.algorithm {
            case .none:
                // TODO: None Security Support
                fatalError()
            case .aes128cfb:
                // TODO: Legacy Security Support
                fatalError()
            case .aes128gcm, .chacha20poly1305:
                // TCP
                let maxAllowedMemorySize = 64 * 1024 * 1024
                guard data.readableBytes + 10 <= maxAllowedMemorySize else {
                    throw CodingError.payloadTooLarge
                }
                
                let overhead = requestHead.algorithm.overhead
                
                let packetLengthSize = requestHead.options.contains(.authenticatedLength) ? 2 + overhead : 2
         
                var shake128: SHAKE128?
                if requestHead.options.contains(.chunkMasking) {
                    shake128 = .init()
                    shake128?.update(data: session.nonce)
                }
                
                let maxPadding = requestHead.options.shouldPadding ? 64 : 0
                
                let maxLength = 2048 - overhead - packetLengthSize - maxPadding
                
                while mutableData.readableBytes > 0 {
                    let message = mutableData.readBytes(length: min(maxLength, mutableData.readableBytes))!
                    
                    var padding = 0
                    if requestHead.options.shouldPadding {
                        assert(shake128 != nil)
                        shake128!.read(digestSize: 2).withUnsafeBytes {
                            assert($0.count == 2)
                            padding = Int($0.load(as: UInt16.self).bigEndian % 64)
                        }
                    }
                    
                    let nonce = withUnsafeBytes(of: packetIndex.bigEndian) {
                        Array($0) + session.nonce[2..<12]
                    }
                    
                    var packet: Data = .init()
                    
                    if requestHead.algorithm == .aes128gcm {
                        let sealedBox = try AES.GCM.seal(message, using: .init(data: session.symmetricKey), nonce: .init(data: nonce))
                        packet = sealedBox.ciphertext + sealedBox.tag
                    } else {
                        let symmetricKey = generateChaChaPolySymmetricKey(inputKeyMaterial: session.symmetricKey)
                        let sealedBox = try ChaChaPoly.seal(message, using: symmetricKey, nonce: .init(data: nonce))
                        packet = sealedBox.ciphertext + sealedBox.tag
                    }

                    assert(packet.count == data.readableBytes + overhead)

                    guard packetLengthSize + packet.count + padding <= 2048 else {
                        throw CodingError.payloadTooLarge
                    }
                    
                    let packetLengthData = try preparePacketLengthData(
                        packetLength: packet.count + padding,
                        nonce: nonce,
                        shake128: &shake128
                    )
                    
                    byteBuffer.writeBytes(packetLengthData)
                    byteBuffer.writeBytes(packet)
                    byteBuffer.writeBytes(Array<UInt8>(capacity: padding))
                    
                    packetIndex += 1
                }
                
                return byteBuffer.withUnsafeReadableBytes {
                    Data($0)
                }
            default:
                fatalError("Unsupported security")
        }
    }
    
    /// Prepare packet length data with specified packetLength, nonce and shake128.
    ///
    /// If request options contains `.authenticatedLength` then packet length data encrypt using AEAD,
    /// else if request options contains `.chunkMasking` then packet length data encrypt using SHAKE128,
    /// otherwise just return plain size data.
    /// - Parameters:
    ///   - packetLength: Data length.
    ///   - nonce: Nonce used to create AEAD nonce.
    ///   - shake128: SHAKE128 object to calculate mask.
    /// - Returns: The encrypted packet length data.
    private func preparePacketLengthData(packetLength: Int, nonce: [UInt8], shake128: inout SHAKE128?) throws -> Data {
        if requestHead.options.contains(.authenticatedLength) {
            return try withUnsafeBytes(of: UInt16(packetLength - requestHead.algorithm.overhead).bigEndian) {
                var symmetricKey = KDF16.deriveKey(inputKeyMaterial: .init(data: session.symmetricKey), info: ["auth_len".data(using: .utf8)!])
                
                if requestHead.algorithm == .aes128gcm {
                    let sealedBox = try AES.GCM.seal($0, using: symmetricKey, nonce: .init(data: nonce))
                    return sealedBox.ciphertext + sealedBox.tag
                } else {
                    symmetricKey = symmetricKey.withUnsafeBytes {
                        generateChaChaPolySymmetricKey(inputKeyMaterial: $0)
                    }
                    let sealedBox = try ChaChaPoly.seal($0, using: symmetricKey, nonce: .init(data: nonce))
                    return sealedBox.ciphertext + sealedBox.tag
                }
            }
        } else if requestHead.options.contains(.chunkMasking) {
            assert(shake128 != nil)
            return shake128!.read(digestSize: 2).withUnsafeBytes {
                assert($0.count == 2)
                let mask = UInt16($0[1]) | UInt16($0[0]) << 8
                return withUnsafeBytes(of: (mask ^ UInt16(packetLength)).bigEndian) {
                    Data($0)
                }
            }
        } else {
            return withUnsafeBytes(of: UInt16(packetLength).bigEndian) {
                Data($0)
            }
        }
    }
    
    /// Prepare END part data.
    ///
    /// If request should trunk stream then return encrypted empty buffer as END part data else just return empty data.
    /// - Returns: Encrypted END part data.
    private func prepareEndPart() throws -> Data {
        guard requestHead.options.contains(.chunkStream) else {
            return .init()
        }

        return try prepareBodyPart(data: .init())
    }
}

func generateCmdKey(_ id: UUID) -> SymmetricKey {
    withUnsafeBytes(of: id) {
        var hasher = Insecure.MD5.init()
        hasher.update(bufferPointer: $0)
        return withUnsafeBytes(of: UUID(uuidString: "C48619FE-8F02-49E0-B9E9-EDF763E17E21")!) {
            hasher.update(bufferPointer: $0)
            return .init(data: hasher.finalize())
        }
    }
}

func generateChaChaPolySymmetricKey<Key>(inputKeyMaterial: Key) -> SymmetricKey where Key: DataProtocol {
    var md5 = Insecure.MD5()
    md5.update(data: inputKeyMaterial)
    return md5.finalize().withUnsafeBytes { ptr in
        var hasher = Insecure.MD5()
        hasher.update(bufferPointer: ptr)
        return hasher.finalize().withUnsafeBytes {
            return .init(data: Array(ptr) + Array($0))
        }
    }
}
