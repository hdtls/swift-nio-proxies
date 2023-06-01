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
import NEMisc
import NEPrettyBytes
import NIOEmbedded
import XCTest

@testable import NESS

final class ResponseDecoderTests: XCTestCase {

  func testDecodeShadowsocksResponseWithAES128GCM() throws {
    let passwordReference = "BeMWIH2K5YtZ"
    let handler = ByteToMessageHandler(
      ResponseDecoder(
        algorithm: .init(rawValue: "AES-128-GCM")!,
        passwordReference: passwordReference
      )
    )
    let channel = EmbeddedChannel(handler: handler)
    var nonce = [UInt8](repeating: 0, count: 12)
    var salt = Array(repeating: UInt8.zero, count: 16)
    salt.withUnsafeMutableBytes {
      $0.initializeWithRandomBytes(count: 16)
    }
    let symmetricKey = hkdfDerivedSymmetricKey(
      secretKey: passwordReference,
      salt: salt,
      outputByteCount: 16
    )
    let packets: [[UInt8]] = [
      [1, 2],
      [3, 4],
      [5],
    ]
    for (i, packet) in packets.enumerated() {
      var byteBuffer = ByteBuffer()
      byteBuffer.writeInteger(UInt16(packet.count))
      var message = byteBuffer.readBytes(length: byteBuffer.readableBytes)!
      byteBuffer.discardReadBytes()

      if i == 0 {
        byteBuffer.writeBytes(salt)
      }

      var sealedBox = try AES.GCM.seal(
        message,
        using: symmetricKey,
        nonce: .init(data: nonce)
      )
      nonce.increment(nonce.count)
      byteBuffer.writeBytes(sealedBox.ciphertext)
      byteBuffer.writeBytes(sealedBox.tag)

      message = packet
      sealedBox = try AES.GCM.seal(
        message,
        using: symmetricKey,
        nonce: .init(data: nonce)
      )
      nonce.increment(nonce.count)
      byteBuffer.writeBytes(sealedBox.ciphertext)
      byteBuffer.writeBytes(sealedBox.tag)

      try channel.writeInbound(byteBuffer)
      XCTAssertEqual(try channel.readInbound(as: ByteBuffer.self), ByteBuffer(bytes: packet))
    }
  }

  func testDecodeShadowsocksResponseWithAES256GCM() throws {
    let passwordReference = "BeMWIH2K5YtZ"
    let handler = ByteToMessageHandler(
      ResponseDecoder(
        algorithm: .init(rawValue: "AES-256-GCM")!,
        passwordReference: passwordReference
      )
    )
    let channel = EmbeddedChannel(handler: handler)
    var nonce = [UInt8](repeating: 0, count: 12)
    var salt = Array(repeating: UInt8.zero, count: 32)
    salt.withUnsafeMutableBytes {
      $0.initializeWithRandomBytes(count: 32)
    }
    let symmetricKey = hkdfDerivedSymmetricKey(
      secretKey: passwordReference,
      salt: salt,
      outputByteCount: 32
    )
    let packets: [[UInt8]] = [
      [1, 2],
      [3, 4],
      [5],
    ]
    for (i, packet) in packets.enumerated() {
      var byteBuffer = ByteBuffer()
      byteBuffer.writeInteger(UInt16(packet.count))
      var message = byteBuffer.readBytes(length: byteBuffer.readableBytes)!
      byteBuffer.discardReadBytes()

      if i == 0 {
        byteBuffer.writeBytes(salt)
      }

      var sealedBox = try AES.GCM.seal(
        message,
        using: symmetricKey,
        nonce: .init(data: nonce)
      )
      nonce.increment(nonce.count)
      byteBuffer.writeBytes(sealedBox.ciphertext)
      byteBuffer.writeBytes(sealedBox.tag)

      message = packet
      sealedBox = try AES.GCM.seal(
        message,
        using: symmetricKey,
        nonce: .init(data: nonce)
      )
      nonce.increment(nonce.count)
      byteBuffer.writeBytes(sealedBox.ciphertext)
      byteBuffer.writeBytes(sealedBox.tag)

      try channel.writeInbound(byteBuffer)
      XCTAssertEqual(try channel.readInbound(as: ByteBuffer.self), ByteBuffer(bytes: packet))
    }
  }

  func testDecodeShadowsocksResponseWithChaCha20Poly1305() throws {
    let passwordReference = "BeMWIH2K5YtZ"
    let handler = ByteToMessageHandler(
      ResponseDecoder(
        algorithm: .init(rawValue: "ChaCha20-Poly1305")!,
        passwordReference: passwordReference
      )
    )
    let channel = EmbeddedChannel(handler: handler)
    var nonce = [UInt8](repeating: 0, count: 12)
    var salt = Array(repeating: UInt8.zero, count: 32)
    salt.withUnsafeMutableBytes {
      $0.initializeWithRandomBytes(count: 32)
    }
    let symmetricKey = hkdfDerivedSymmetricKey(
      secretKey: passwordReference,
      salt: salt,
      outputByteCount: 32
    )
    let packets: [[UInt8]] = [
      [1, 2],
      [3, 4],
      [5],
    ]
    for (i, packet) in packets.enumerated() {
      var byteBuffer = ByteBuffer()
      byteBuffer.writeInteger(UInt16(packet.count))
      var message = byteBuffer.readBytes(length: byteBuffer.readableBytes)!
      byteBuffer.discardReadBytes()

      if i == 0 {
        byteBuffer.writeBytes(salt)
      }

      var sealedBox = try ChaChaPoly.seal(
        message,
        using: symmetricKey,
        nonce: .init(data: nonce)
      )
      nonce.increment(nonce.count)
      byteBuffer.writeBytes(sealedBox.ciphertext)
      byteBuffer.writeBytes(sealedBox.tag)

      message = packet
      sealedBox = try ChaChaPoly.seal(
        message,
        using: symmetricKey,
        nonce: .init(data: nonce)
      )
      nonce.increment(nonce.count)
      byteBuffer.writeBytes(sealedBox.ciphertext)
      byteBuffer.writeBytes(sealedBox.tag)

      try channel.writeInbound(byteBuffer)
      XCTAssertEqual(try channel.readInbound(as: ByteBuffer.self), ByteBuffer(bytes: packet))
    }
  }
}
