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
import NIOCore
import NIONetbotMisc
import PrettyBytes
import SHAKE128

final public class LengthFieldBasedFrameEncoder: MessageToByteEncoder {

    public typealias OutboundIn = ByteBuffer

    private let symmetricKey: SecureBytes
    private let nonce: SecureBytes
    private let configuration: Configuration
    private var frameOffset: UInt16 = 0
    private lazy var shake128: SHAKE128 = {
        var shake128 = SHAKE128()
        shake128.update(data: nonce)
        return shake128
    }()

    public init(symmetricKey: SecureBytes, nonce: SecureBytes, configuration: Configuration) {
        self.configuration = configuration
        self.symmetricKey = symmetricKey
        self.nonce = nonce
    }

    public func encode(data: ByteBuffer, out: inout ByteBuffer) throws {
        switch configuration.algorithm {
            case .aes128gcm, .chacha20poly1305:
                out.writeBytes(try prepareFrame(data: data))
            case .aes128cfb, .none, .zero:
                fatalError(
                    "\(self) \(#function) for \(configuration.algorithm) not yet implemented."
                )
        }
    }

    /// Prepare frame data with specified data.
    /// - Parameter data: Original data.
    /// - Returns: Encrypted frame data.
    private func prepareFrame(data: ByteBuffer) throws -> Data {
        var mutableData = data

        // TCP
        let maxAllowedMemorySize = 64 * 1024 * 1024
        guard data.readableBytes + 10 <= maxAllowedMemorySize else {
            throw CodingError.payloadTooLarge
        }

        let overhead = configuration.algorithm.overhead

        let packetLengthSize =
            configuration.options.contains(.authenticatedLength) ? 2 + overhead : 2

        let maxPadding = configuration.options.shouldPadding ? 64 : 0

        let maxLength = 2048 - overhead - packetLengthSize - maxPadding

        var frameBuffer: Data = .init()

        while mutableData.readableBytes > 0 {
            let message = mutableData.readBytes(length: min(maxLength, mutableData.readableBytes))!

            var padding = 0
            if configuration.options.shouldPadding {
                shake128.read(digestSize: 2).withUnsafeBytes {
                    padding = Int($0.load(as: UInt16.self).bigEndian % 64)
                }
            }

            let nonce = withUnsafeBytes(of: frameOffset.bigEndian) {
                Array($0) + Array(self.nonce.prefix(12).suffix(10))
            }

            var frame: Data = .init()

            if configuration.algorithm == .aes128gcm {
                let sealedBox = try AES.GCM.seal(
                    message,
                    using: .init(data: symmetricKey),
                    nonce: .init(data: nonce)
                )
                frame = sealedBox.ciphertext + sealedBox.tag
            } else {
                let symmetricKey = generateChaChaPolySymmetricKey(inputKeyMaterial: symmetricKey)
                let sealedBox = try ChaChaPoly.seal(
                    message,
                    using: symmetricKey,
                    nonce: .init(data: nonce)
                )
                frame = sealedBox.ciphertext + sealedBox.tag
            }

            guard packetLengthSize + frame.count + padding <= 2048 else {
                throw CodingError.payloadTooLarge
            }

            let frameLengthData = try prepareFrameLengthData(
                frameLength: frame.count + padding,
                nonce: nonce
            )

            frameBuffer.append(frameLengthData)
            frameBuffer.append(frame)
            frameBuffer.append(contentsOf: SecureBytes(count: padding))

            frameOffset += 1
        }

        return frameBuffer
    }

    /// Prepare frame length field data with specified frameLength and nonce.
    ///
    /// If request options contains `.authenticatedLength` then packet length data encrypt using AEAD,
    /// else if request options contains `.chunkMasking` then packet length data encrypt using SHAKE128,
    /// otherwise just return plain size data.
    /// - Parameters:
    ///   - frameLength: Frame data length.
    ///   - nonce: Nonce used to create AEAD nonce.
    /// - Returns: The encrypted frame length field data.
    private func prepareFrameLengthData(frameLength: Int, nonce: [UInt8]) throws -> Data {
        if configuration.options.contains(.authenticatedLength) {
            return try withUnsafeBytes(
                of: UInt16(frameLength - configuration.algorithm.overhead).bigEndian
            ) {
                var symmetricKey = KDF16.deriveKey(
                    inputKeyMaterial: .init(data: symmetricKey),
                    info: ["auth_len".data(using: .utf8)!]
                )

                if configuration.algorithm == .aes128gcm {
                    let sealedBox = try AES.GCM.seal(
                        $0,
                        using: symmetricKey,
                        nonce: .init(data: nonce)
                    )
                    return sealedBox.ciphertext + sealedBox.tag
                } else {
                    symmetricKey = symmetricKey.withUnsafeBytes {
                        generateChaChaPolySymmetricKey(inputKeyMaterial: $0)
                    }
                    let sealedBox = try ChaChaPoly.seal(
                        $0,
                        using: symmetricKey,
                        nonce: .init(data: nonce)
                    )
                    return sealedBox.ciphertext + sealedBox.tag
                }
            }
        } else if configuration.options.contains(.masking) {
            return shake128.read(digestSize: 2).withUnsafeBytes {
                let mask = $0.load(as: UInt16.self).bigEndian
                return withUnsafeBytes(of: (mask ^ UInt16(frameLength)).bigEndian) {
                    Data($0)
                }
            }
        } else {
            return withUnsafeBytes(of: UInt16(frameLength).bigEndian) {
                Data($0)
            }
        }
    }

    /// Prepare last frame data.
    ///
    /// If request should trunk stream then return encrypted empty buffer as END part data else just return empty data.
    /// - Returns: Encrypted last frame data.
    private func prepareLastFrame() throws -> Data {
        guard configuration.options.contains(.chunked) else {
            return .init()
        }

        return try prepareFrame(data: .init())
    }
}

#if swift(>=5.7)
@available(*, unavailable)
extension LengthFieldBasedFrameEncoder: Sendable {}
#endif
