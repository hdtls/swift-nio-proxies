//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import NEAddressProcessing
import NIOCore
import NIOEmbedded
import XCTest

@testable import NESS

final class RequestEncoderTests: XCTestCase {

  func testEncodeShadowsocksRequestWithAES128GCM() throws {
    let passwordReference = "BeMWIH2K5YtZ"
    let destinationAddress = Address.hostPort(host: "192.168.1.1", port: 80)
    let handler = RequestEncoder(
      algorithm: .init(rawValue: "AES-128-GCM")!,
      passwordReference: passwordReference,
      destinationAddress: destinationAddress
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

      var combined: [UInt8]!
      var actualData: Data!
      var ciphertext: Data!
      var encryptedDataLength: Int = 0
      var packet: ByteBuffer!

      if i == 0 {
        // The first packet contains salt value.
        packet = try channel.readOutbound(as: ByteBuffer.self)
        XCTAssertNotNil(packet)
        XCTAssertEqual(packet.readableBytes, 16)

        // Read salt value.
        guard packet.readableBytes == 16 else {
          XCTFail("Invalid salt packet.")
          return
        }
        let salt = packet.readBytes(length: 16)!

        symmetricKey = hkdfDerivedSymmetricKey(
          secretKey: passwordReference,
          salt: salt,
          outputByteCount: 16
        )

        // Read encrypted address buffer.
        packet = try channel.readOutbound(as: ByteBuffer.self)
        XCTAssertNotNil(packet)

        guard packet.readableBytes > 18 else {
          XCTFail(
            "Packet should contains at least 18 bytes data to decode encrypt packet length, but got \(packet.readableBytes) bytes."
          )
          return
        }
        combined = nonce + packet.readBytes(length: 18)!
        ciphertext = try AES.GCM.open(.init(combined: combined), using: symmetricKey)
        encryptedDataLength = ciphertext.withUnsafeBytes {
          Int($0.bindMemory(to: UInt16.self).baseAddress!.pointee.bigEndian) + 16
        }
        nonce.increment(nonce.count)

        guard packet.readableBytes == encryptedDataLength else {
          XCTFail(
            "Packet should contains at least \(encryptedDataLength) bytes data to decode address data, but got \(packet.readableBytes) bytes."
          )
          return
        }
        combined = nonce + packet.readBytes(length: encryptedDataLength)!
        var actualData = try AES.GCM.open(.init(combined: combined), using: symmetricKey)
        nonce.increment(nonce.count)
        XCTAssertEqual(try actualData.readAddress(), destinationAddress)
      }

      packet = try channel.readOutbound(as: ByteBuffer.self)
      XCTAssertNotNil(packet)

      // Read encrypted request data.
      guard packet.readableBytes > 18 else {
        XCTFail(
          "Packet should contains at least 18 bytes data to decode encrypt packet length, but got \(packet.readableBytes) bytes."
        )
        return
      }
      combined = nonce + packet.readBytes(length: 18)!
      ciphertext = try AES.GCM.open(.init(combined: combined), using: symmetricKey)
      encryptedDataLength = ciphertext.withUnsafeBytes {
        Int($0.bindMemory(to: UInt16.self).baseAddress!.pointee.bigEndian) + 16
      }
      nonce.increment(nonce.count)

      guard packet.readableBytes == encryptedDataLength else {
        XCTFail(
          "Packet should contains at least \(encryptedDataLength) bytes data to decode trucked packet data, but got \(packet.readableBytes) bytes."
        )
        return
      }
      combined = nonce + packet.readBytes(length: encryptedDataLength)!
      actualData = try AES.GCM.open(.init(combined: combined), using: symmetricKey)
      nonce.increment(nonce.count)
      XCTAssertEqual(actualData, Data(bytesToWrite))
      XCTAssertEqual(packet.readableBytes, 0)
    }

    XCTAssertNil(try channel.readOutbound(as: ByteBuffer.self))
  }

  func testEncodeShadowsocksRequestWithAES256GCM() throws {
    let passwordReference = "BeMWIH2K5YtZ"
    let destinationAddress = Address.hostPort(host: "192.168.1.1", port: 80)
    let handler = RequestEncoder(
      algorithm: .init(rawValue: "AES-256-GCM")!,
      passwordReference: passwordReference,
      destinationAddress: destinationAddress
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

      var combined: [UInt8]!
      var actualData: Data!
      var ciphertext: Data!
      var encryptedDataLength: Int = 0
      var packet: ByteBuffer!

      if i == 0 {
        // The first packet contains salt value.
        packet = try channel.readOutbound(as: ByteBuffer.self)
        XCTAssertNotNil(packet)
        XCTAssertEqual(packet.readableBytes, 32)

        // Read salt value.
        guard packet.readableBytes == 32 else {
          XCTFail("Invalid salt packet.")
          return
        }
        let salt = packet.readBytes(length: 32)!

        symmetricKey = hkdfDerivedSymmetricKey(
          secretKey: passwordReference,
          salt: salt,
          outputByteCount: 32
        )

        // Read encrypted address buffer.
        packet = try channel.readOutbound(as: ByteBuffer.self)
        XCTAssertNotNil(packet)

        guard packet.readableBytes > 18 else {
          XCTFail(
            "Packet should contains at least 18 bytes data to decode encrypt packet length, but got \(packet.readableBytes) bytes."
          )
          return
        }
        combined = nonce + packet.readBytes(length: 18)!
        ciphertext = try AES.GCM.open(.init(combined: combined), using: symmetricKey)
        encryptedDataLength = ciphertext.withUnsafeBytes {
          Int($0.bindMemory(to: UInt16.self).baseAddress!.pointee.bigEndian) + 16
        }
        nonce.increment(nonce.count)

        guard packet.readableBytes == encryptedDataLength else {
          XCTFail(
            "Packet should contains at least \(encryptedDataLength) bytes data to decode address data, but got \(packet.readableBytes) bytes."
          )
          return
        }
        combined = nonce + packet.readBytes(length: encryptedDataLength)!
        var actualData = try AES.GCM.open(.init(combined: combined), using: symmetricKey)
        nonce.increment(nonce.count)
        XCTAssertEqual(try actualData.readAddress(), destinationAddress)
      }

      packet = try channel.readOutbound(as: ByteBuffer.self)
      XCTAssertNotNil(packet)

      // Read encrypted request data.
      guard packet.readableBytes > 18 else {
        XCTFail(
          "Packet should contains at least 18 bytes data to decode encrypt packet length, but got \(packet.readableBytes) bytes."
        )
        return
      }
      combined = nonce + packet.readBytes(length: 18)!
      ciphertext = try AES.GCM.open(.init(combined: combined), using: symmetricKey)
      encryptedDataLength = ciphertext.withUnsafeBytes {
        Int($0.bindMemory(to: UInt16.self).baseAddress!.pointee.bigEndian) + 16
      }
      nonce.increment(nonce.count)

      guard packet.readableBytes == encryptedDataLength else {
        XCTFail(
          "Packet should contains at least \(encryptedDataLength) bytes data to decode trucked packet data, but got \(packet.readableBytes) bytes."
        )
        return
      }
      combined = nonce + packet.readBytes(length: encryptedDataLength)!
      actualData = try AES.GCM.open(.init(combined: combined), using: symmetricKey)
      nonce.increment(nonce.count)
      XCTAssertEqual(actualData, Data(bytesToWrite))
      XCTAssertEqual(packet.readableBytes, 0)
    }

    XCTAssertNil(try channel.readOutbound(as: ByteBuffer.self))
  }

  func testEncodeShadowsocksRequestWithChaCha20Poly1305() throws {
    let passwordReference = "BeMWIH2K5YtZ"
    let destinationAddress = Address.hostPort(host: "192.168.1.1", port: 80)
    let handler = RequestEncoder(
      algorithm: .init(rawValue: "ChaCha20-Poly1305")!,
      passwordReference: passwordReference,
      destinationAddress: destinationAddress
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

      var combined: [UInt8]!
      var actualData: Data!
      var ciphertext: Data!
      var encryptedDataLength: Int = 0
      var packet: ByteBuffer!

      if i == 0 {
        // The first packet contains salt value.
        packet = try channel.readOutbound(as: ByteBuffer.self)
        XCTAssertNotNil(packet)
        XCTAssertEqual(packet.readableBytes, 32)

        // Read salt value.
        guard packet.readableBytes == 32 else {
          XCTFail("Invalid salt packet.")
          return
        }
        let salt = packet.readBytes(length: 32)!

        symmetricKey = hkdfDerivedSymmetricKey(
          secretKey: passwordReference,
          salt: salt,
          outputByteCount: 32
        )

        // Read encrypted address buffer.
        packet = try channel.readOutbound(as: ByteBuffer.self)
        XCTAssertNotNil(packet)

        guard packet.readableBytes > 18 else {
          XCTFail(
            "Packet should contains at least 18 bytes data to decode encrypt packet length, but got \(packet.readableBytes) bytes."
          )
          return
        }
        combined = nonce + packet.readBytes(length: 18)!
        ciphertext = try ChaChaPoly.open(.init(combined: combined), using: symmetricKey)
        encryptedDataLength = ciphertext.withUnsafeBytes {
          Int($0.bindMemory(to: UInt16.self).baseAddress!.pointee.bigEndian) + 16
        }
        nonce.increment(nonce.count)

        guard packet.readableBytes == encryptedDataLength else {
          XCTFail(
            "Packet should contains at least \(encryptedDataLength) bytes data to decode address data, but got \(packet.readableBytes) bytes."
          )
          return
        }
        combined = nonce + packet.readBytes(length: encryptedDataLength)!
        var actualData = try ChaChaPoly.open(.init(combined: combined), using: symmetricKey)
        nonce.increment(nonce.count)
        XCTAssertEqual(try actualData.readAddress(), destinationAddress)
      }

      packet = try channel.readOutbound(as: ByteBuffer.self)
      XCTAssertNotNil(packet)

      // Read encrypted request data.
      guard packet.readableBytes > 18 else {
        XCTFail(
          "Packet should contains at least 18 bytes data to decode encrypt packet length, but got \(packet.readableBytes) bytes."
        )
        return
      }
      combined = nonce + packet.readBytes(length: 18)!
      ciphertext = try ChaChaPoly.open(.init(combined: combined), using: symmetricKey)
      encryptedDataLength = ciphertext.withUnsafeBytes {
        Int($0.bindMemory(to: UInt16.self).baseAddress!.pointee.bigEndian) + 16
      }
      nonce.increment(nonce.count)

      guard packet.readableBytes == encryptedDataLength else {
        XCTFail(
          "Packet should contains at least \(encryptedDataLength) bytes data to decode trucked packet data, but got \(packet.readableBytes) bytes."
        )
        return
      }
      combined = nonce + packet.readBytes(length: encryptedDataLength)!
      actualData = try ChaChaPoly.open(.init(combined: combined), using: symmetricKey)
      nonce.increment(nonce.count)
      XCTAssertEqual(actualData, Data(bytesToWrite))
      XCTAssertEqual(packet.readableBytes, 0)
    }

    XCTAssertNil(try channel.readOutbound(as: ByteBuffer.self))
  }
}
