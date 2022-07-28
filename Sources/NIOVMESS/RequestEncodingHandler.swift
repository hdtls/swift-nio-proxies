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

@_implementationOnly import CCryptoBoringSSL
import Crypto
import Foundation
import Logging
import NIOCore
import NIONetbotMisc
import SHAKE128

final public class RequestEncodingHandler: ChannelOutboundHandler {

    public typealias OutboundIn = ByteBuffer

    public typealias OutboundOut = ByteBuffer

    private let logger: Logger

    private let authenticationCode: UInt8

    private let symmetricKey: SecureBytes

    private let nonce: SecureBytes

    /// Request encoder configuration object.
    private let configuration: Configuration

    private let forceAEADEncoding: Bool

    /// Request address.
    private let address: NetAddress

    private var encoder: LengthFieldBasedFrameEncoder

    private var buffer: ByteBuffer?

    private enum State {
        case idle
        case preparing
        case processing
        case complete
        case fail(Error)

        var isIdle: Bool {
            guard case .idle = self else {
                return false
            }
            return true
        }
    }

    private var state: State = .idle

    /// Initialize an instance of `RequestHeaderEncoder` with specified logger, authenticationCode, symmetricKey, nonce, configuration, forceAEADEncoding and address.
    /// - Parameters:
    ///   - logger: The logger object use to logging.
    ///   - authenticationCode: Request header authentication code.
    ///   - symmetricKey: SymmetricKey of the encrpytor.
    ///   - nonce: Nonce of the encryptor.
    ///   - configuration: The configuration object contains encoder configurations.
    ///   - forceAEADEncoding: A boolean value determinse whether encoder should use AEAD encoding.
    ///   - taskAddress: The requet address.
    public init(
        logger: Logger,
        authenticationCode: UInt8,
        symmetricKey: SecureBytes,
        nonce: SecureBytes,
        configuration: Configuration,
        forceAEADEncoding: Bool = true,
        taskAddress: NetAddress
    ) {
        self.logger = logger
        self.authenticationCode = authenticationCode
        self.symmetricKey = symmetricKey
        self.nonce = nonce
        self.configuration = configuration
        self.forceAEADEncoding = forceAEADEncoding
        self.address = taskAddress
        self.encoder = .init(
            logger: logger,
            symmetricKey: symmetricKey,
            nonce: nonce,
            configuration: configuration
        )
    }

    public func handlerAdded(context: ChannelHandlerContext) {
        precondition(state.isIdle, "Illegal state when adding to channel: \(state)")
        state = .preparing
        buffer = context.channel.allocator.buffer(capacity: 256)
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        state = .complete
        buffer = nil
    }

    public func write(
        context: ChannelHandlerContext,
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    ) {
        do {
            buffer?.clear()

            switch state {
                case .idle:
                    preconditionFailure(
                        "\(self) \(#function) called before it was added to a channel."
                    )
                case .preparing:
                    buffer?.writeBytes(try prepareHeadPart())
                    state = .processing
                    break
                case .processing:
                    break
                case .complete:
                    return
                case .fail:
                    return
            }

            try encoder.encode(data: unwrapOutboundIn(data), out: &buffer!)
            context.write(wrapOutboundOut(buffer!), promise: promise)
        } catch {
            state = .fail(error)
            promise?.fail(error)
            context.fireErrorCaught(error)
        }
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
        result += try prepareAuthenticationInfoPart(timestamp: timestamp)
        result += try prepareInstructionPart(timestamp: timestamp)
        return result
    }

    /// Prepare HEAD authentication info part data with specified timestamp.
    ///
    /// If use AEAD to encrypt request just return empty data instead.
    /// - Parameter timestamp: UTC UInt64 timestamp.
    /// - Returns: Encrypted authentication info part data.
    private func prepareAuthenticationInfoPart(timestamp: UInt64) throws -> Data {
        guard !forceAEADEncoding else {
            return .init()
        }

        return withUnsafeBytes(of: configuration.id) {
            var hasher = HMAC<Insecure.MD5>(key: .init(data: $0))
            return withUnsafeBytes(of: timestamp.bigEndian) {
                hasher.update(data: $0)
                return Data(hasher.finalize())
            }
        }
    }

    /// Prepare HEAD instruction part data with specified timestamp.
    /// - Parameter timestamp: UTC UInt64 timestamp.
    /// - Returns: Encrypted instruction part data.
    private func prepareInstructionPart(timestamp: UInt64) throws -> Data {
        var buffer = ByteBuffer()
        buffer.writeInteger(ProtocolVersion.v1.rawValue)
        buffer.writeBytes(nonce)
        buffer.writeBytes(symmetricKey)
        buffer.writeInteger(authenticationCode)
        buffer.writeInteger(configuration.options.rawValue)

        let padding = UInt8.random(in: 0...16)
        buffer.writeInteger((padding << 4) | configuration.algorithm.rawValue)
        // Write zero as keeper.
        buffer.writeInteger(UInt8(0))
        buffer.writeInteger(configuration.command.rawValue)

        if configuration.command != .mux {
            buffer.writeAddress(address)
        }

        if padding > 0 {
            buffer.writeBytes(SecureBytes(count: Int(padding)))
        }

        buffer.writeInteger(
            buffer.withUnsafeReadableBytes {
                CCryptoBoringSSL_OPENSSL_hash32($0.baseAddress, $0.count)
            }
        )

        let inputKeyMaterial = generateCmdKey(configuration.id)
        if forceAEADEncoding {
            let authenticatedData = try generateAuthenticatedData(inputKeyMaterial)
            let randomPath = Array(SecureBytes(count: 8))

            var info = [
                [],
                authenticatedData,
                randomPath,
            ]

            let sealedLengthBox: AES.GCM.SealedBox = try withUnsafeBytes(
                of: UInt16(buffer.readableBytes).bigEndian
            ) {
                info[0] = Array(KDFSaltConstVMessHeaderPayloadLengthAEADKey)
                let symmetricKey = KDF16.deriveKey(inputKeyMaterial: inputKeyMaterial, info: info)

                info[0] = Array(KDFSaltConstVMessHeaderPayloadLengthAEADIV)
                let nonce = try KDF12.deriveKey(inputKeyMaterial: inputKeyMaterial, info: info)
                    .withUnsafeBytes { ptr in
                        try AES.GCM.Nonce.init(data: ptr)
                    }
                return try AES.GCM.seal(
                    $0,
                    using: symmetricKey,
                    nonce: nonce,
                    authenticating: authenticatedData
                )
            }

            let sealedPayloadBox: AES.GCM.SealedBox = try buffer.withUnsafeReadableBytes {
                info[0] = Array(KDFSaltConstVMessHeaderPayloadAEADKey)
                let symmetricKey = KDF16.deriveKey(inputKeyMaterial: inputKeyMaterial, info: info)

                info[0] = Array(KDFSaltConstVMessHeaderPayloadAEADIV)
                let nonce = try KDF12.deriveKey(inputKeyMaterial: inputKeyMaterial, info: info)
                    .withUnsafeBytes { ptr in
                        try AES.GCM.Nonce.init(data: ptr)
                    }
                return try AES.GCM.seal(
                    $0,
                    using: symmetricKey,
                    nonce: nonce,
                    authenticating: authenticatedData
                )
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

            let symmetricKey = UnsafeMutablePointer<AES_KEY>.allocate(
                capacity: MemoryLayout<AES_KEY>.size
            )
            symmetricKey.initialize(to: .init())
            defer {
                symmetricKey.deinitialize(count: MemoryLayout<AES_KEY>.size)
                symmetricKey.deallocate()
            }

            inputKeyMaterial.withUnsafeBytes {
                _ = CCryptoBoringSSL_AES_set_encrypt_key(
                    $0.bindMemory(to: UInt8.self).baseAddress,
                    128,
                    symmetricKey
                )
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
                            UnsafeMutablePointer(
                                mutating: ivPtr.bindMemory(to: UInt8.self).baseAddress
                            ),
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
        var byteBuffer = withUnsafeBytes(
            of: UInt64(Date().timeIntervalSince1970).bigEndian,
            Array.init
        )
        byteBuffer += Array(SecureBytes(count: 4))
        byteBuffer += withUnsafeBytes(of: CRC32.checksum(byteBuffer).bigEndian, Array.init)

        let inputKeyMaterial = KDF16.deriveKey(
            inputKeyMaterial: key,
            info: [Array(KDFSaltConstAuthIDEncryptionKey)]
        )

        let symmetricKey = UnsafeMutablePointer<AES_KEY>.allocate(
            capacity: MemoryLayout<AES_KEY>.size
        )
        symmetricKey.initialize(to: .init())
        defer {
            symmetricKey.deinitialize(count: MemoryLayout<AES_KEY>.size)
            symmetricKey.deallocate()
        }

        try inputKeyMaterial.withUnsafeBytes {
            guard
                CCryptoBoringSSL_AES_set_encrypt_key(
                    $0.bindMemory(to: UInt8.self).baseAddress,
                    128,
                    symmetricKey
                ) == 0
            else {
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
}
