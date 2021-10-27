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
@testable import Netbot

final class ProxyPolicyTests: XCTestCase {
    
    func testParsingDirectPolicy() throws {
        let stringLiteral = "DIRECT = direct"
        let policy = try DirectPolicy.init(stringLiteral: stringLiteral)

        XCTAssertEqual(policy.name, "DIRECT")
    }
    
    func testDirectPolicyEncoding() throws {
        let expected = "DIRECT = direct"
        let policy = try DirectPolicy.init(stringLiteral: expected)
        
        let data = try JSONEncoder().encode(policy)
        let stringLiteral = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed) as? String
        XCTAssertEqual(stringLiteral, expected)
    }
    
    func testParsingRejectPolicy() throws {
        let stringLiteral = "REJECT = reject"
        let policy = try RejectPolicy.init(stringLiteral: stringLiteral)
        
        XCTAssertEqual(policy.name, "REJECT")
    }
    
    func testRejectPolicyEncoding() throws {
        let expected = "REJECT = reject"
        let policy = try RejectPolicy.init(stringLiteral: expected)
        
        let data = try JSONEncoder().encode(policy)
        let stringLiteral = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed) as? String
        XCTAssertEqual(stringLiteral, expected)
    }
    
    func testParsingRejectTinyGifPolicy() throws {
        let stringLiteral = "REJECT-TINYGIF = reject-tinygif"
        let policy = try RejectTinyGifPolicy.init(stringLiteral: stringLiteral)
        
        XCTAssertEqual(policy.name, "REJECT-TINYGIF")
    }
    
    func testRejectTinyGifPolicyEncoding() throws {
        let expected = "REJECT-TINYGIF = reject-tinygif"
        let policy = try RejectTinyGifPolicy.init(stringLiteral: expected)
        
        let data = try JSONEncoder().encode(policy)
        let stringLiteral = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed) as? String
        XCTAssertEqual(stringLiteral, expected)
    }
    
    func testParsingShadowsocksPolicy() throws {
        let stringLiteral = "SHADOWSOCKS = ss, server-hostname=127.0.0.1, server-port=8389, algorithm=chacha20-ietf-poly1305, password=password, allow-udp-relay=true, tfo=true"

        let policy = try ShadowsocksPolicy.init(stringLiteral: stringLiteral)

        XCTAssertEqual(policy.name, "SHADOWSOCKS")
        XCTAssertEqual(policy.configuration.serverPort, 8389)
        XCTAssertEqual(policy.configuration.serverHostname, "127.0.0.1")
        XCTAssertEqual(policy.configuration.password, "password")
        XCTAssertEqual(policy.configuration.algorithm, "chacha20-ietf-poly1305")
        XCTAssertEqual(policy.configuration.allowUDPRelay, true)
        XCTAssertEqual(policy.configuration.tfo, true)
        
        let policies = try JSONDecoder().decode([ShadowsocksPolicy].self, from: JSONSerialization.data(withJSONObject: [stringLiteral], options: .fragmentsAllowed))
        XCTAssertNotNil(policies.first)
        let policy1 = policies.first!
        XCTAssertEqual(policy.name, policy1.name)
        XCTAssertEqual(policy.configuration.serverPort, policy1.configuration.serverPort)
        XCTAssertEqual(policy.configuration.serverHostname, policy1.configuration.serverHostname)
        XCTAssertEqual(policy.configuration.password, policy1.configuration.password)
        XCTAssertEqual(policy.configuration.algorithm, policy1.configuration.algorithm)
        XCTAssertEqual(policy.configuration.allowUDPRelay, policy1.configuration.allowUDPRelay)
        XCTAssertEqual(policy.configuration.tfo, policy1.configuration.tfo)
    }
    
    func testParsingShadowsocksPolicyWithStringThatMissingBoolValueField() throws {
        let stringLiteral = "SHADOWSOCKS = ss, server-hostname=127.0.0.1, server-port=8389, algorithm=chacha20-ietf-poly1305, password=password"
        
        let policy = try ShadowsocksPolicy.init(stringLiteral: stringLiteral)
        
        XCTAssertEqual(policy.name, "SHADOWSOCKS")
        XCTAssertEqual(policy.configuration.serverPort, 8389)
        XCTAssertEqual(policy.configuration.serverHostname, "127.0.0.1")
        XCTAssertEqual(policy.configuration.password, "password")
        XCTAssertEqual(policy.configuration.algorithm, "chacha20-ietf-poly1305")
        XCTAssertEqual(policy.configuration.allowUDPRelay, false)
        XCTAssertEqual(policy.configuration.tfo, false)
    }
    
    func testParsingShadowsocksPolicyFieldRequires() {
        var stringLiteral = "SHADOWSOCKS = ss"
        XCTAssertThrowsError(try ShadowsocksPolicy.init(stringLiteral: stringLiteral))
        
        stringLiteral = "SHADOWSOCKS = ss, server-hostname=127.0.0.1"
        XCTAssertThrowsError(try ShadowsocksPolicy.init(stringLiteral: stringLiteral))

        stringLiteral = "SHADOWSOCKS = ss, server-hostname=127.0.0.1, server-port=8389"
        XCTAssertThrowsError(try ShadowsocksPolicy.init(stringLiteral: stringLiteral))
        
        stringLiteral = "SHADOWSOCKS = ss, server-hostname=127.0.0.1, server-port=8389, algorithm=chacha20-ietf-poly1305"
        XCTAssertThrowsError(try ShadowsocksPolicy.init(stringLiteral: stringLiteral))
        
        stringLiteral = "SHADOWSOCKS = ss, server-hostname=127.0.0.1, server-port=8389, algorithm=chacha20-ietf-poly1305, password=password"
        XCTAssertNoThrow(try ShadowsocksPolicy.init(stringLiteral: stringLiteral))
    }
    
    func testShadowoscksPolicyEncoding() throws {
        let expected = "SHADOWSOCKS = ss, algorithm=chacha20-ietf-poly1305, allow-udp-relay=true, password=password, server-hostname=127.0.0.1, server-port=8389, tfo=true"
        let policy = try ShadowsocksPolicy.init(stringLiteral: expected)
            
        let data = try JSONEncoder().encode(policy)
        let stringLiteral = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed) as? String
        XCTAssertEqual(stringLiteral, expected)
    }
    
    func testParsingSOCKS5Policy() throws {
        let stringLiteral = "SOCKS = socks5, password=password, server-port=8385, server-hostname=127.0.0.1, username=username"
        
        let policy = try SOCKS5Policy.init(stringLiteral: stringLiteral)
        
        XCTAssertEqual(policy.name, "SOCKS")
        XCTAssertEqual(policy.configuration.serverPort, 8385)
        XCTAssertEqual(policy.configuration.serverHostname, "127.0.0.1")
        XCTAssertEqual(policy.configuration.password, "password")
       
        let policies = try JSONDecoder().decode([SOCKS5Policy].self, from: JSONSerialization.data(withJSONObject: [stringLiteral], options: .fragmentsAllowed))
        XCTAssertNotNil(policies.first)
        let policy1 = policies.first!
        XCTAssertEqual(policy.name, policy1.name)
        XCTAssertEqual(policy.configuration.serverPort, policy1.configuration.serverPort)
        XCTAssertEqual(policy.configuration.serverHostname, policy1.configuration.serverHostname)
        XCTAssertEqual(policy.configuration.password, policy1.configuration.password)
    }
    
    func testParsingSOCKS5PolicyFieldRequires() {
        var stringLiteral = "SOCKS = socks5"
        XCTAssertThrowsError(try SOCKS5Policy.init(stringLiteral: stringLiteral))
        
        stringLiteral = "SOCKS = socks5, server-hostname=127.0.0.1"
        XCTAssertThrowsError(try SOCKS5Policy.init(stringLiteral: stringLiteral))
        
        stringLiteral = "SOCKS = socks5, server-hostname=127.0.0.1, server-port=8389"
        XCTAssertNoThrow(try SOCKS5Policy.init(stringLiteral: stringLiteral))
    }
    
    func testSOCKS5PolicyEncoding() throws {
        let expected = "SOCKS = socks5, password=password, server-hostname=127.0.0.1, server-port=8385, username=username"
        let policy = try SOCKS5Policy.init(stringLiteral: expected)
        
        let data = try JSONEncoder().encode(policy)
        let stringLiteral = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed) as? String
        XCTAssertEqual(stringLiteral, expected)
    }
 
    func testParsingSOCKS5TLSPolicy() throws {
        let stringLiteral = "SOCKS TLS = socks5-tls, password=password, server-port=8385, server-hostname=socks5-tls.com, username=username"
        
        let policy = try SOCKS5TLSPolicy.init(stringLiteral: stringLiteral)
        
        XCTAssertEqual(policy.name, "SOCKS TLS")
        XCTAssertEqual(policy.configuration.serverPort, 8385)
        XCTAssertEqual(policy.configuration.serverHostname, "socks5-tls.com")
        XCTAssertEqual(policy.configuration.password, "password")
        
        let policies = try JSONDecoder().decode([SOCKS5TLSPolicy].self, from: JSONSerialization.data(withJSONObject: [stringLiteral], options: .fragmentsAllowed))
        XCTAssertNotNil(policies.first)
        let policy1 = policies.first!
        XCTAssertEqual(policy.name, policy1.name)
        XCTAssertEqual(policy.configuration.serverPort, policy1.configuration.serverPort)
        XCTAssertEqual(policy.configuration.serverHostname, policy1.configuration.serverHostname)
        XCTAssertEqual(policy.configuration.password, policy1.configuration.password)
    }
    
    func testParsingSOCKS5TLSPolicyFieldRequires() {
        var stringLiteral = "SOCKS TLS = socks5-tls"
        XCTAssertThrowsError(try SOCKS5TLSPolicy.init(stringLiteral: stringLiteral))
        
        stringLiteral = "SOCKS TLS = socks5-tls, server-hostname=socks5-tls.com"
        XCTAssertThrowsError(try SOCKS5TLSPolicy.init(stringLiteral: stringLiteral))
        
        stringLiteral = "SOCKS TLS = socks5-tls, server-hostname=socks5-tls.com, server-port=8389"
        XCTAssertNoThrow(try SOCKS5TLSPolicy.init(stringLiteral: stringLiteral))
    }
    
    func testSOCKS5TLSPolicyEncoding() throws {
        let expected = "SOCKS TLS = socks5-tls, password=password, server-hostname=socks5-tls.com, server-port=8385, username=username"
        let policy = try SOCKS5TLSPolicy.init(stringLiteral: expected)
        
        let data = try JSONEncoder().encode(policy)
        let stringLiteral = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed) as? String
        XCTAssertEqual(stringLiteral, expected)
    }
    
    func testParsingHTTPSProxyPolicy() throws {
        let stringLiteral = "HTTPS = https, password=password, server-hostname=https.com, server-port=8385, username=username"
        
        let policy = try HTTPSProxyPolicy.init(stringLiteral: stringLiteral)
        
        XCTAssertEqual(policy.name, "HTTPS")
        XCTAssertEqual(policy.configuration.serverPort, 8385)
        XCTAssertEqual(policy.configuration.serverHostname, "https.com")
        XCTAssertEqual(policy.configuration.password, "password")
        
        let policies = try JSONDecoder().decode([HTTPSProxyPolicy].self, from: JSONSerialization.data(withJSONObject: [stringLiteral], options: .fragmentsAllowed))
        XCTAssertNotNil(policies.first)
        let policy1 = policies.first!
        XCTAssertEqual(policy.name, policy1.name)
        XCTAssertEqual(policy.configuration.serverPort, policy1.configuration.serverPort)
        XCTAssertEqual(policy.configuration.serverHostname, policy1.configuration.serverHostname)
        XCTAssertEqual(policy.configuration.password, policy1.configuration.password)
    }
    
    func testParsingHTTPSPolicyFieldRequires() {
        var stringLiteral = "HTTPS = https"
        XCTAssertThrowsError(try HTTPSProxyPolicy.init(stringLiteral: stringLiteral))
        
        stringLiteral = "HTTPS = https, server-hostname=https.com"
        XCTAssertThrowsError(try HTTPSProxyPolicy.init(stringLiteral: stringLiteral))
        
        stringLiteral = "HTTPS = https, server-hostname=https.com, server-port=8389"
        XCTAssertNoThrow(try HTTPSProxyPolicy.init(stringLiteral: stringLiteral))
    }
    
    func testHTTPSPolicyEncoding() throws {
        let expected = "HTTPS = https, password=password, server-hostname=https.com, server-port=8385, username=username"
        let policy = try HTTPSProxyPolicy.init(stringLiteral: expected)
        
        let data = try JSONEncoder().encode(policy)
        let stringLiteral = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed) as? String
        XCTAssertEqual(stringLiteral, expected)
    }
    
    func testParsingHTTPProxyPolicy() throws {
        let stringLiteral = "HTTP = http, password=password, server-hostname=https.com, server-port=8385, username=username"
        
        let policy = try HTTPProxyPolicy.init(stringLiteral: stringLiteral)
        
        XCTAssertEqual(policy.name, "HTTP")
        XCTAssertEqual(policy.configuration.serverPort, 8385)
        XCTAssertEqual(policy.configuration.serverHostname, "https.com")
        XCTAssertEqual(policy.configuration.password, "password")
        
        let policies = try JSONDecoder().decode([HTTPProxyPolicy].self, from: JSONSerialization.data(withJSONObject: [stringLiteral], options: .fragmentsAllowed))
        XCTAssertNotNil(policies.first)
        let policy1 = policies.first!
        XCTAssertEqual(policy.name, policy1.name)
        XCTAssertEqual(policy.configuration.serverPort, policy1.configuration.serverPort)
        XCTAssertEqual(policy.configuration.serverHostname, policy1.configuration.serverHostname)
        XCTAssertEqual(policy.configuration.password, policy1.configuration.password)
    }
    
    func testParsingHTTPPolicyFieldRequires() {
        var stringLiteral = "HTTP = http"
        XCTAssertThrowsError(try HTTPProxyPolicy.init(stringLiteral: stringLiteral))
        
        stringLiteral = "HTTP = http, server-hostname=127.0.0.1"
        XCTAssertThrowsError(try HTTPProxyPolicy.init(stringLiteral: stringLiteral))
        
        stringLiteral = "HTTP = http, server-hostname=127.0.0.1, server-port=8389"
        XCTAssertNoThrow(try HTTPProxyPolicy.init(stringLiteral: stringLiteral))
    }
    
    func testHTTPPolicyEncoding() throws {
        let expected = "HTTP = http, password=password, server-hostname=127.0.0.1, server-port=8385, username=username"
        let policy = try HTTPProxyPolicy.init(stringLiteral: expected)
        
        let data = try JSONEncoder().encode(policy)
        let stringLiteral = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed) as? String
        XCTAssertEqual(stringLiteral, expected)
    }
    
    func testParsingProxyPolicy() throws {
        let direct = "DIRECT = direct"
        let reject = "REJECT = reject"
        let rejectTinyGif = "REJECT-TINYGIF = reject-tinygif"
        let ss = "SHADOWSOCKS = ss, server-hostname=127.0.0.1, server-port=8389, algorithm=chacha20-ietf-poly1305, password=password, allow-udp-relay=true, tfo=true"
        let socks5 = "SOCKS = socks5, password=password, server-port=8385, server-hostname=127.0.0.1, username=username"
        let socks5TLS = "SOCKS TLS = socks5-tls, password=password, server-port=8385, server-hostname=socks5-tls.com, username=username"
        let https = "HTTPS = https, password=password, server-hostname=https.com, server-port=8385, username=username"
        let http = "HTTP = http, password=password, server-hostname=https.com, server-port=8385, username=username"
    
        guard case .direct(let policy) = try ProxyPolicy.init(stringLiteral: direct) else {
            XCTFail()
            return
        }
        XCTAssertEqual(policy, try DirectPolicy.init(stringLiteral: direct))
        
        guard case .reject(let policy) = try ProxyPolicy.init(stringLiteral: reject) else {
            XCTFail()
            return
        }
        XCTAssertEqual(policy, try RejectPolicy.init(stringLiteral: reject))

        guard case .rejectTinyGif(let policy) = try ProxyPolicy.init(stringLiteral: rejectTinyGif) else {
            XCTFail()
            return
        }
        XCTAssertEqual(policy, try RejectTinyGifPolicy.init(stringLiteral: rejectTinyGif))
        
        guard case .shadowsocks(let policy) = try ProxyPolicy.init(stringLiteral: ss) else {
            XCTFail()
            return
        }
        XCTAssertEqual(policy, try ShadowsocksPolicy.init(stringLiteral: ss))

        guard case .socks5(let policy) = try ProxyPolicy.init(stringLiteral: socks5) else {
            XCTFail()
            return
        }
        XCTAssertEqual(policy, try SOCKS5Policy.init(stringLiteral: socks5))

        guard case .socks5TLS(let policy) = try ProxyPolicy.init(stringLiteral: socks5TLS) else {
            XCTFail()
            return
        }
        XCTAssertEqual(policy, try SOCKS5TLSPolicy.init(stringLiteral: socks5TLS))

        guard case .http(let policy) = try ProxyPolicy.init(stringLiteral: http) else {
            XCTFail()
            return
        }
        XCTAssertEqual(policy, try HTTPProxyPolicy.init(stringLiteral: http))

        guard case .https(let policy) = try ProxyPolicy.init(stringLiteral: https) else {
            XCTFail()
            return
        }
        XCTAssertEqual(policy, try HTTPSProxyPolicy.init(stringLiteral: https))
    }
    
    func testProxyPolicyEncoding() throws {
        let direct = "DIRECT = direct"
        let reject = "REJECT = reject"
        let rejectTinyGif = "REJECT-TINYGIF = reject-tinygif"
        let ss = "SHADOWSOCKS = ss, algorithm=chacha20-ietf-poly1305, allow-udp-relay=true, password=password, server-hostname=127.0.0.1, server-port=8389, tfo=true"
        let socks5 = "SOCKS = socks5, password=password, server-hostname=127.0.0.1, server-port=8385, username=username"
        let socks5TLS = "SOCKS TLS = socks5-tls, password=password, server-hostname=socks5-tls.com, server-port=8385, username=username"
        let https = "HTTPS = https, password=password, server-hostname=https.com, server-port=8385, username=username"
        let http = "HTTP = http, password=password, server-hostname=https.com, server-port=8385, username=username"
        
        func assertEncodingPolicyStringLiteral(_ expected: String) throws {
            let data = try JSONEncoder().encode(try ProxyPolicy.init(stringLiteral: expected))
            let stringLiteral = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed) as? String
            XCTAssertEqual(stringLiteral, expected)
        }
        
        try assertEncodingPolicyStringLiteral(direct)
        try assertEncodingPolicyStringLiteral(reject)
        try assertEncodingPolicyStringLiteral(rejectTinyGif)
        try assertEncodingPolicyStringLiteral(ss)
        try assertEncodingPolicyStringLiteral(socks5)
        try assertEncodingPolicyStringLiteral(socks5TLS)
        try assertEncodingPolicyStringLiteral(http)
        try assertEncodingPolicyStringLiteral(https)
    }
}
