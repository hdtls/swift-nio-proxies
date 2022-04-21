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

import ConnectionPool
import Foundation
import NetbotCore
import EraseNilDecoding
import NetbotSS

public protocol Policy: ConnectionPoolSource {
    
    associatedtype Configuration
    
    static var schema: String { get }
    
    var configuration: Configuration { get set }
    
    var name: String { get set }
    
    var taskAddress: NetAddress? { get set }
    
    init()
}

enum PolicyJSONKeys: String, CodingKey {
    case name
    case configuration
}

public enum ProxyPolicy: Codable {
    
    case direct(DirectPolicy)
    case reject(RejectPolicy)
    case rejectTinyGif(RejectTinyGifPolicy)
    case shadowsocks(ShadowsocksPolicy)
    case socks5(SOCKS5Policy)
    case socks5TLS(SOCKS5OverTLSPolicy)
    case http(HTTPProxyPolicy)
    case https(HTTPSProxyPolicy)
    case vmess(VMESSPolicy)
    
    public var name: String {
        switch self {
            case .direct(let underlying):
                return underlying.name
            case .reject(let underlying):
                return underlying.name
            case .rejectTinyGif(let underlying):
                return underlying.name
            case .shadowsocks(let underlying):
                return underlying.name
            case .socks5(let underlying):
                return underlying.name
            case .socks5TLS(let underlying):
                return underlying.name
            case .http(let underlying):
                return underlying.name
            case .https(let underlying):
                return underlying.name
            case .vmess(let underlying):
                return underlying.name
        }
    }
    
    public var taskAddress: NetAddress? {
        set {
            switch self {
                case .direct(var underlying):
                    underlying.taskAddress = newValue
                    self = .direct(underlying)
                case .reject(var underlying):
                    underlying.taskAddress = newValue
                    self = .reject(underlying)
                case .rejectTinyGif(var underlying):
                    underlying.taskAddress = newValue
                    self = .rejectTinyGif(underlying)
                case .shadowsocks(var underlying):
                    underlying.taskAddress = newValue
                    self = .shadowsocks(underlying)
                case .socks5(var underlying):
                    underlying.taskAddress = newValue
                    self = .socks5(underlying)
                case .socks5TLS(var underlying):
                    underlying.taskAddress = newValue
                    self = .socks5TLS(underlying)
                case .http(var underlying):
                    underlying.taskAddress = newValue
                    self = .http(underlying)
                case .https(var underlying):
                    underlying.taskAddress = newValue
                    self = .https(underlying)
                case .vmess(var underlying):
                    underlying.taskAddress = newValue
                    self = .vmess(underlying)
            }
        }
        get {
            switch self {
                case .direct(let underlying):
                    return underlying.taskAddress
                case .reject(let underlying):
                    return underlying.taskAddress
                case .rejectTinyGif(let underlying):
                    return underlying.taskAddress
                case .shadowsocks(let underlying):
                    return underlying.taskAddress
                case .socks5(let underlying):
                    return underlying.taskAddress
                case .socks5TLS(let underlying):
                    return underlying.taskAddress
                case .http(let underlying):
                    return underlying.taskAddress
                case .https(let underlying):
                    return underlying.taskAddress
                case .vmess(let underlying):
                    return underlying.taskAddress
            }
        }
    }

    public func encode(to encoder: Encoder) throws {
        switch self {
            case .direct(let underlying):
                try underlying.encode(to: encoder)
            case .reject(let underlying):
                try underlying.encode(to: encoder)
            case .rejectTinyGif(let underlying):
                try underlying.encode(to: encoder)
            case .shadowsocks(let underlying):
                try underlying.encode(to: encoder)
            case .socks5(let underlying):
                try underlying.encode(to: encoder)
            case .socks5TLS(let underlying):
                try underlying.encode(to: encoder)
            case .http(let underlying):
                try underlying.encode(to: encoder)
            case .https(let underlying):
                try underlying.encode(to: encoder)
            case .vmess(let underlying):
                try underlying.encode(to: encoder)
        }
    }
    
    private enum CodingKeys: String, CodingKey {
        case type
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        switch try container.decode(String.self, forKey: .type).uppercased() {
            case "DIRECT":
                self = .direct(try DirectPolicy.init(from: decoder))
            case "HTTP":
                self = .http(try HTTPProxyPolicy(from: decoder))
            case "HTTPS":
                self = .https(try HTTPSProxyPolicy(from: decoder))
            case "REJECT":
                self = .reject(.init())
            case "REJECT-TINYGIF":
                self = .rejectTinyGif(.init())
            case "SS":
                self = .shadowsocks(try ShadowsocksPolicy(from: decoder))
            case "SOCKS5":
                self = .socks5(try SOCKS5Policy(from: decoder))
            case "SOCKS5-TLS":
                self = .socks5TLS(try SOCKS5OverTLSPolicy(from: decoder))
            case "VMESS":
                self = .vmess(try VMESSPolicy(from: decoder))
            default:
                throw ConfigurationSerializationError.dataCorrupted
        }
    }
    
    public func makeConnection(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<Channel> {
        switch self {
            case .direct(let underlying):
                return underlying.makeConnection(logger: logger, on: eventLoop)
            case .reject(let underlying):
                return underlying.makeConnection(logger: logger, on: eventLoop)
            case .rejectTinyGif(let underlying):
                return underlying.makeConnection(logger: logger, on: eventLoop)
            case .shadowsocks(let underlying):
                return underlying.makeConnection(logger: logger, on: eventLoop)
            case .socks5(let underlying):
                return underlying.makeConnection(logger: logger, on: eventLoop)
            case .socks5TLS(let underlying):
                return underlying.makeConnection(logger: logger, on: eventLoop)
            case .http(let underlying):
                return underlying.makeConnection(logger: logger, on: eventLoop)
            case .https(let underlying):
                return underlying.makeConnection(logger: logger, on: eventLoop)
            case .vmess(let underlying):
                return underlying.makeConnection(logger: logger, on: eventLoop)
        }
    }
}

public struct DirectPolicy: Codable, Equatable, Policy {
        
    typealias CodingKeys = PolicyJSONKeys
    
    public struct Configuration: Codable, Equatable {}
    
    public static let schema: String = "direct"
    
    public var configuration: Configuration
    
    public var name: String
    
    public var taskAddress: NetAddress?
    
    public init() {
        self.init(taskAddress: nil)
    }
    
    public init(taskAddress: NetAddress?) {
        self.taskAddress = taskAddress
        self.name = "DIRECT"
        self.configuration = .init()
    }
}

public struct RejectPolicy: Codable, Equatable, Policy {
    
    typealias CodingKeys = PolicyJSONKeys

    public struct Configuration: Codable, Equatable {}

    public static var schema: String = "reject"
    
    public var configuration: Configuration
    
    public var name: String
    
    public var taskAddress: NetAddress?
    
    public init() {
        self.init(taskAddress: nil)
    }
    
    public init(taskAddress: NetAddress?) {
        self.taskAddress = taskAddress
        self.name = "REJECT"
        self.configuration = .init()
    }
}

public struct RejectTinyGifPolicy: Codable, Equatable, Policy {
    
    typealias CodingKeys = PolicyJSONKeys

    public struct Configuration: Codable, Equatable {}

    public static var schema: String = "reject-tinygif"
    
    public var configuration: Configuration
    
    public var name: String
    
    public var taskAddress: NetAddress?
    
    public init() {
        self.init(taskAddress: nil)
    }
    
    public init(taskAddress: NetAddress?) {
        self.taskAddress = taskAddress
        self.name = "REJECT-TINYGIF"
        self.configuration = .init()
    }
}

public struct ShadowsocksPolicy: Codable, Equatable, Policy {
    
    typealias CodingKeys = PolicyJSONKeys

    public struct Configuration: NetbotSS.ConfigurationProtocol, Codable, Equatable {
        
        public var serverAddress: String
        
        public var port: Int
        
        public var algorithm: NetbotSS.CryptoAlgorithm
        
        @EraseNilToFalse public var enableUdpRelay: Bool
        
        public var password: String
        
        @EraseNilToFalse public var enableTfo: Bool
        
        public var passwordReference: String {
            password
        }
        
        public init(serverAddress: String,
                    port: Int,
                    algorithm: NetbotSS.CryptoAlgorithm,
                    password: String,
                    enableUdpRelay: Bool,
                    enableTfo: Bool) {
            self.serverAddress = serverAddress
            self.port = port
            self.algorithm = algorithm
            self.password = password
            self.enableUdpRelay = enableUdpRelay
            self.enableTfo = enableTfo
        }
        
        public init() {
            self.init(serverAddress: "", port: 0, algorithm: .aes128Gcm, password: "", enableUdpRelay: false, enableTfo: false)
        }
    }
    
    public static let schema: String = "ss"
    
    public var configuration: Configuration
    
    public var name: String
    
    public var taskAddress: NetAddress?
    
    public init() {
        self.init(name: "Shadowsocks", configuration: .init())
    }
    
    public init(name: String, configuration: Configuration) {
        self.name = name
        self.configuration = configuration
    }
}

extension NetbotSS.CryptoAlgorithm: Codable {}

public struct SOCKS5Policy: Codable, Equatable, Policy {
    
    typealias CodingKeys = PolicyJSONKeys

    public struct Configuration: Codable, Equatable {
        
        public var password: String?
        public var username: String?
        public var serverAddress: String = ""
        public var port: Int = 0
    }
    
    public static let schema: String = "socks5"
    
    public var configuration: Configuration
    
    public var name: String
    
    public var taskAddress: NetAddress?
    
    public init() {
        self.init(name: "SOCKS5", configuration: .init())
    }
    
    public init(name: String, configuration: Configuration) {
        self.name = name
        self.configuration = configuration
    }
}

public struct SOCKS5OverTLSPolicy: Codable, Equatable, Policy {
    
    typealias CodingKeys = PolicyJSONKeys

    public struct Configuration: Codable, Equatable {
        
        // TODO: Allow user add client certificate.
        //        public var clientCerficateString: String?
        public var sni: String?
        public var password: String?
        public var username: String?
        public var serverAddress: String = ""
        public var port: Int = 0
        @EraseNilToFalse public var skipCertificateVerification: Bool = false
    }
    
    public static let schema: String = "socks5-tls"
    
    public var name: String
    
    public var configuration: Configuration
    
    public var taskAddress: NetAddress?
    
    public init() {
        self.init(name: "SOCKS5OverTLS", configuration: .init())
    }
    
    public init(name: String, configuration: Configuration) {
        self.name = name
        self.configuration = configuration
    }
}

public struct HTTPProxyPolicy: Codable, Equatable, Policy {
    
    typealias CodingKeys = PolicyJSONKeys

    public struct Configuration: Codable, Equatable {
        
        public var password: String?
        public var username: String?
        public var serverAddress: String = ""
        public var port: Int = 0
        @EraseNilToFalse public var performHttpTunneling: Bool = false
    }
    
    public static let schema: String = "http"
    /// Name for proxy.
    public var name: String
    public var configuration: Configuration
    public var taskAddress: NetAddress?
    
    public init() {
        self.name = "HTTP"
        self.configuration = .init()
    }
}

public struct HTTPSProxyPolicy: Codable, Equatable, Policy {
    
    typealias CodingKeys = PolicyJSONKeys

    public struct Configuration: Codable, Equatable {
        
        // TODO: Allow user add client certificate.
        //        public var clientCerficateString: String?
        public var sni: String?
        public var password: String?
        public var username: String?
        public var serverAddress: String = ""
        public var port: Int = 0
        
        @EraseNilToFalse public var performHttpTunneling: Bool = false

        @EraseNilToFalse public var skipCertificateVerification: Bool = false
    }
    
    public static var schema: String = "https"
    
    /// Name for proxy.
    public var name: String
    public var configuration: Configuration
    public var taskAddress: NetAddress?
    
    public init() {
        self.name = "HTTPS"
        self.configuration = .init()
    }
}

public struct VMESSPolicy: Codable, Equatable, Policy {
    
    typealias CodingKeys = PolicyJSONKeys

    public static var schema: String = "vmess"
    
    public struct Configuration: Codable, Equatable {
        
        public var username: String?
        public var serverAddress: String = ""
        public var port: Int = 0
    }
    
    public var configuration: Configuration
    
    public var name: String
    
    public var taskAddress: NetAddress?
    
    public init() {
        self.init(name: "VMESS", configuration: .init())
    }
    
    public init(name: String, configuration: Configuration) {
        self.name = name
        self.configuration = configuration
    }
}

// Just a namespacing
enum Builtin {}

extension Builtin {
    
    static var policies: [ProxyPolicy] = [.direct(.init()), .reject(.init()), .rejectTinyGif(.init())]
}
