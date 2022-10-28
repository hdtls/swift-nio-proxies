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

import Crypto
import NIO
import NIONetbotMisc
import XCTest

@testable import NIOSS

final class RequestEncoderTests: XCTestCase {

    func testEncodeShadowsocksRequestWithAES128GCM() throws {
        let passwordReference = "BeMWIH2K5YtZ"
        let destinationAddress = NetAddress.socketAddress(
            try! .init(ipAddress: "192.168.1.1", port: 80)
        )
        let handler = MessageToByteHandler(
            RequestEncoder.init(
                algorithm: .init(rawValue: "AES-128-GCM")!,
                passwordReference: passwordReference,
                destinationAddress: destinationAddress
            )
        )
        let channel = EmbeddedChannel(handler: handler)

        var nonce = [UInt8](repeating: 0, count: 12)

        let packets: [[UInt8]] = [
            [1, 2],
            [3, 4],
            [5],
        ]

        var symmetricKey: SymmetricKey!

        for (i, bytesToWrite) in packets.enumerated() {
            try channel.writeOutbound(ByteBuffer(bytes: bytesToWrite))
            var byteBuffer = try channel.readOutbound(as: ByteBuffer.self)!

            var combined: [UInt8]!
            var actualData: Data!
            var ciphertext: Data!
            var encryptedDataLength: Int = 0

            // Only first packet contains address info.
            if i == 0 {
                // Read salt value.
                let salt = byteBuffer.readBytes(length: 16)!

                symmetricKey = hkdfDerivedSymmetricKey(
                    secretKey: passwordReference,
                    salt: salt,
                    outputByteCount: 16
                )

                // Read encrypted address buffer.
                combined = nonce + byteBuffer.readBytes(length: 18)!
                ciphertext = try AES.GCM.open(.init(combined: combined), using: symmetricKey)
                encryptedDataLength = ciphertext.withUnsafeBytes {
                    Int($0.bindMemory(to: UInt16.self).baseAddress!.pointee.bigEndian) + 16
                }
                nonce.increment(nonce.count)

                combined = nonce + byteBuffer.readBytes(length: encryptedDataLength)!
                var actualData = try AES.GCM.open(.init(combined: combined), using: symmetricKey)
                nonce.increment(nonce.count)
                XCTAssertEqual(try actualData.readAddress(), destinationAddress)
            }

            // Read encrypted request data.
            combined = nonce + byteBuffer.readBytes(length: 18)!
            ciphertext = try AES.GCM.open(.init(combined: combined), using: symmetricKey)
            encryptedDataLength = ciphertext.withUnsafeBytes {
                Int($0.bindMemory(to: UInt16.self).baseAddress!.pointee.bigEndian) + 16
            }
            nonce.increment(nonce.count)

            combined = nonce + byteBuffer.readBytes(length: encryptedDataLength)!
            actualData = try AES.GCM.open(.init(combined: combined), using: symmetricKey)
            nonce.increment(nonce.count)
            XCTAssertEqual(actualData, Data(bytesToWrite))
            XCTAssertEqual(byteBuffer.readableBytes, 0)
        }
    }

    func testEncodeShadowsocksRequestWithAES256GCM() throws {
        let passwordReference = "BeMWIH2K5YtZ"
        let destinationAddress = NetAddress.socketAddress(
            try! .init(ipAddress: "192.168.1.1", port: 80)
        )
        let handler = MessageToByteHandler(
            RequestEncoder.init(
                algorithm: .init(rawValue: "AES-256-GCM")!,
                passwordReference: passwordReference,
                destinationAddress: destinationAddress
            )
        )
        let channel = EmbeddedChannel(handler: handler)

        var nonce = [UInt8](repeating: 0, count: 12)

        let packets: [[UInt8]] = [
            [1, 2],
            [3, 4],
            [5],
        ]

        var symmetricKey: SymmetricKey!

        for (i, bytesToWrite) in packets.enumerated() {
            try channel.writeOutbound(ByteBuffer(bytes: bytesToWrite))
            var byteBuffer = try channel.readOutbound(as: ByteBuffer.self)!

            var combined: [UInt8]!
            var actualData: Data!
            var ciphertext: Data!
            var encryptedDataLength: Int = 0

            // Only first packet contains address info.
            if i == 0 {
                // Read salt value.
                let salt = byteBuffer.readBytes(length: 32)!

                symmetricKey = hkdfDerivedSymmetricKey(
                    secretKey: passwordReference,
                    salt: salt,
                    outputByteCount: 32
                )

                // Read encrypted address buffer.
                combined = nonce + byteBuffer.readBytes(length: 18)!
                ciphertext = try AES.GCM.open(.init(combined: combined), using: symmetricKey)
                encryptedDataLength = ciphertext.withUnsafeBytes {
                    Int($0.bindMemory(to: UInt16.self).baseAddress!.pointee.bigEndian) + 16
                }
                nonce.increment(nonce.count)

                combined = nonce + byteBuffer.readBytes(length: encryptedDataLength)!
                var actualData = try AES.GCM.open(.init(combined: combined), using: symmetricKey)
                nonce.increment(nonce.count)
                XCTAssertEqual(try actualData.readAddress(), destinationAddress)
            }

            // Read encrypted request data.
            combined = nonce + byteBuffer.readBytes(length: 18)!
            ciphertext = try AES.GCM.open(.init(combined: combined), using: symmetricKey)
            encryptedDataLength = ciphertext.withUnsafeBytes {
                Int($0.bindMemory(to: UInt16.self).baseAddress!.pointee.bigEndian) + 16
            }
            nonce.increment(nonce.count)

            combined = nonce + byteBuffer.readBytes(length: encryptedDataLength)!
            actualData = try AES.GCM.open(.init(combined: combined), using: symmetricKey)
            nonce.increment(nonce.count)
            XCTAssertEqual(actualData, Data(bytesToWrite))
            XCTAssertEqual(byteBuffer.readableBytes, 0)
        }
    }

    func testEncodeShadowsocksRequestWithChaCha20Poly1305() throws {
        let passwordReference = "BeMWIH2K5YtZ"
        let destinationAddress = NetAddress.socketAddress(
            try! .init(ipAddress: "192.168.1.1", port: 80)
        )
        let handler = MessageToByteHandler(
            RequestEncoder.init(
                algorithm: .init(rawValue: "ChaCha20-Poly1305")!,
                passwordReference: passwordReference,
                destinationAddress: destinationAddress
            )
        )
        let channel = EmbeddedChannel(handler: handler)

        var nonce = [UInt8](repeating: 0, count: 12)

        let packets: [[UInt8]] = [
            [1, 2],
            [3, 4],
            [5],
        ]

        var symmetricKey: SymmetricKey!

        for (i, bytesToWrite) in packets.enumerated() {
            try channel.writeOutbound(ByteBuffer(bytes: bytesToWrite))
            var byteBuffer = try channel.readOutbound(as: ByteBuffer.self)!

            var combined: [UInt8]!
            var actualData: Data!
            var ciphertext: Data!
            var encryptedDataLength: Int = 0

            // Only first packet contains address info.
            if i == 0 {
                // Read salt value.
                let salt = byteBuffer.readBytes(length: 32)!

                symmetricKey = hkdfDerivedSymmetricKey(
                    secretKey: passwordReference,
                    salt: salt,
                    outputByteCount: 32
                )

                // Read encrypted address buffer.
                combined = nonce + byteBuffer.readBytes(length: 18)!
                ciphertext = try ChaChaPoly.open(.init(combined: combined), using: symmetricKey)
                encryptedDataLength = ciphertext.withUnsafeBytes {
                    Int($0.bindMemory(to: UInt16.self).baseAddress!.pointee.bigEndian) + 16
                }
                nonce.increment(nonce.count)

                combined = nonce + byteBuffer.readBytes(length: encryptedDataLength)!
                var actualData = try ChaChaPoly.open(.init(combined: combined), using: symmetricKey)
                nonce.increment(nonce.count)
                XCTAssertEqual(try actualData.readAddress(), destinationAddress)
            }

            // Read encrypted request data.
            combined = nonce + byteBuffer.readBytes(length: 18)!
            ciphertext = try ChaChaPoly.open(.init(combined: combined), using: symmetricKey)
            encryptedDataLength = ciphertext.withUnsafeBytes {
                Int($0.bindMemory(to: UInt16.self).baseAddress!.pointee.bigEndian) + 16
            }
            nonce.increment(nonce.count)

            combined = nonce + byteBuffer.readBytes(length: encryptedDataLength)!
            actualData = try ChaChaPoly.open(.init(combined: combined), using: symmetricKey)
            nonce.increment(nonce.count)
            XCTAssertEqual(actualData, Data(bytesToWrite))
            XCTAssertEqual(byteBuffer.readableBytes, 0)
        }
    }
}
