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

import XCTest

@testable import NIONetbotMisc

class NetAddressTests: XCTestCase {

    func testEquatableWorks() {
        let first = NetAddress.domainPort("localhost", 80)
        let second = NetAddress.domainPort("localhost", 80)
        let third = NetAddress.socketAddress(try! .init(ipAddress: "127.0.0.1", port: 80))
        let fourth = NetAddress.socketAddress(try! .init(ipAddress: "127.0.0.1", port: 80))
        XCTAssertEqual(first, second)
        XCTAssertEqual(third, fourth)
        XCTAssertNotEqual(first, third)
    }

    func testApplyingDomainPortAddress() {
        var packet = Data()
        var buffer = ByteBuffer()
        let address = NetAddress.domainPort("localhost", 80)
        let expectedAddress: [UInt8] = [
            0x03, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x00, 0x50,
        ]
        XCTAssertEqual(packet.writeAddress(address), expectedAddress.count)
        XCTAssertEqual(buffer.writeAddress(address), expectedAddress.count)
        XCTAssertEqual(packet.count, 13)
        XCTAssertEqual(buffer.readableBytes, 13)
        XCTAssertEqual([UInt8](packet), expectedAddress)
        XCTAssertEqual(buffer.readBytes(length: buffer.readableBytes), expectedAddress)
    }

    func testApplyingIPv4SocketAddress() {
        var packet = Data()
        var buffer = ByteBuffer()
        let address = NetAddress.socketAddress(try! .init(ipAddress: "127.0.0.1", port: 80))
        XCTAssertEqual(packet.writeAddress(address), 7)
        XCTAssertEqual(buffer.writeAddress(address), 7)
        XCTAssertEqual(packet.count, 7)
        XCTAssertEqual(buffer.readableBytes, 7)
        XCTAssertEqual(packet.removeFirst(), 0x01)
        XCTAssertEqual(buffer.readInteger(as: UInt8.self), 0x01)
        XCTAssertEqual(Array(packet.prefix(4)), [0x7F, 0x00, 0x00, 0x01])
        packet.removeFirst(4)
        XCTAssertEqual(buffer.readBytes(length: 4), [0x7F, 0x00, 0x00, 0x01])
        packet.prefix(MemoryLayout<in_port_t>.size).withUnsafeBytes {
            XCTAssertEqual($0.bindMemory(to: in_port_t.self).baseAddress?.pointee.bigEndian, 80)
        }
        packet.removeFirst(MemoryLayout<in_port_t>.size)
        XCTAssertEqual(buffer.readInteger(as: in_port_t.self), 80)
        XCTAssertEqual(packet.count, 0)
        XCTAssertEqual(buffer.readableBytes, 0)
    }

    func testApplyingIPv6SocketAddress() {
        var packet = Data()
        var buffer = ByteBuffer()
        let address = NetAddress.socketAddress(try! .init(ipAddress: "::1", port: 80))
        XCTAssertEqual(packet.writeAddress(address), 19)
        XCTAssertEqual(buffer.writeAddress(address), 19)
        XCTAssertEqual(packet.count, 19)
        XCTAssertEqual(buffer.readableBytes, 19)
        XCTAssertEqual(packet.removeFirst(), 0x04)
        XCTAssertEqual(buffer.readInteger(as: UInt8.self), 0x04)
        XCTAssertEqual(
            Array(packet.prefix(16)),
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ]
        )
        packet.removeFirst(16)
        XCTAssertEqual(
            buffer.readBytes(length: 16),
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ]
        )
        packet.prefix(MemoryLayout<in_port_t>.size).withUnsafeBytes {
            XCTAssertEqual($0.bindMemory(to: in_port_t.self).baseAddress?.pointee.bigEndian, 80)
        }
        packet.removeFirst(MemoryLayout<in_port_t>.size)
        XCTAssertEqual(buffer.readInteger(as: in_port_t.self), 80)
        XCTAssertEqual(packet.count, 0)
        XCTAssertEqual(buffer.readableBytes, 0)
    }

    func testRejectWrongAddressType() {
        let expectedAddress: [UInt8] = [0x02, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x50]
        var packet = Data(expectedAddress)
        var buffer = ByteBuffer(bytes: expectedAddress)
        do {
            _ = try packet.readAddress()
        } catch {
            XCTAssertTrue(error is SocketAddressError)
        }
        do {
            _ = try buffer.readAddress()
        } catch {
            XCTAssertTrue(error is SocketAddressError)
        }
        XCTAssertEqual(packet.count, expectedAddress.count)
        XCTAssertEqual(buffer.readableBytes, expectedAddress.count)
        XCTAssertEqual(Array(packet.prefix(expectedAddress.count)), expectedAddress)
        XCTAssertEqual(buffer.readBytes(length: expectedAddress.count), expectedAddress)
    }

    func testReadAddressButBufferIsNotEnoughToReadAsNetAddress() {
        let expectedAddress: [UInt8] = [0x01, 0x7F, 0x00, 0x00, 0x01, 0x00]
        var packet = Data(expectedAddress)
        var buffer = ByteBuffer(bytes: expectedAddress)
        do {
            let addr1 = try packet.readAddress()
            let addr2 = try buffer.readAddress()
            XCTAssertNil(addr1)
            XCTAssertNil(addr2)
            XCTAssertEqual(packet.count, expectedAddress.count)
            XCTAssertEqual(buffer.readableBytes, expectedAddress.count)
            XCTAssertEqual(Array(packet.prefix(expectedAddress.count)), expectedAddress)
            XCTAssertEqual(buffer.readBytes(length: expectedAddress.count), expectedAddress)
        } catch {
            XCTFail()
        }
    }

    func testReadAddressButBufferIsEmpty() {
        let expectedAddress: [UInt8] = []
        var packet = Data(expectedAddress)
        var buffer = ByteBuffer(bytes: expectedAddress)
        do {
            let addr1 = try packet.readAddress()
            let addr2 = try buffer.readAddress()
            XCTAssertNil(addr1)
            XCTAssertNil(addr2)
            XCTAssertEqual(packet.count, expectedAddress.count)
            XCTAssertEqual(buffer.readableBytes, expectedAddress.count)
            XCTAssertEqual(Array(packet.prefix(expectedAddress.count)), expectedAddress)
            XCTAssertEqual(buffer.readBytes(length: expectedAddress.count), expectedAddress)
        } catch {
            XCTFail()
        }
    }

    func testReadIPv4Address() {
        let expectedAddress: [UInt8] = [0x01, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x50]
        var packet = Data(expectedAddress)
        var buffer = ByteBuffer(bytes: expectedAddress)
        var addr1: NetAddress?
        var addr2: NetAddress?
        XCTAssertNoThrow(addr1 = try packet.readAddress())
        XCTAssertNoThrow(addr2 = try buffer.readAddress())
        XCTAssertNotNil(addr1)
        XCTAssertNotNil(addr2)
        XCTAssertEqual(addr1, .socketAddress(try! .init(ipAddress: "127.0.0.1", port: 80)))
        XCTAssertEqual(addr2, .socketAddress(try! .init(ipAddress: "127.0.0.1", port: 80)))
        XCTAssertEqual(packet.count, 0)
        XCTAssertEqual(buffer.readableBytes, 0)
    }

    func testReadIPv6Address() {
        let expectedAddress: [UInt8] = [
            0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x50,
        ]
        var packet = Data(expectedAddress)
        var buffer = ByteBuffer(bytes: expectedAddress)
        var addr1: NetAddress?
        var addr2: NetAddress?
        XCTAssertNoThrow(addr1 = try packet.readAddress())
        XCTAssertNoThrow(addr2 = try buffer.readAddress())
        XCTAssertNotNil(addr1)
        XCTAssertNotNil(addr2)
        XCTAssertEqual(addr1, .socketAddress(try! .init(ipAddress: "::1", port: 80)))
        XCTAssertEqual(addr2, .socketAddress(try! .init(ipAddress: "::1", port: 80)))
        XCTAssertEqual(packet.count, 0)
        XCTAssertEqual(buffer.readableBytes, 0)
    }

    func testReadDomain() {
        let expectedAddress: [UInt8] = [
            0x03, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x00, 0x50,
        ]
        var packet = Data(expectedAddress)
        var buffer = ByteBuffer(bytes: expectedAddress)
        var addr1: NetAddress?
        var addr2: NetAddress?
        XCTAssertNoThrow(addr1 = try packet.readAddress())
        XCTAssertNoThrow(addr2 = try buffer.readAddress())
        XCTAssertNotNil(addr1)
        XCTAssertNotNil(addr2)
        XCTAssertEqual(addr1, .domainPort("localhost", 80))
        XCTAssertEqual(addr2, .domainPort("localhost", 80))
        XCTAssertEqual(packet.count, 0)
        XCTAssertEqual(buffer.readableBytes, 0)
    }
}
