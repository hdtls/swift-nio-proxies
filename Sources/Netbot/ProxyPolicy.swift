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

public struct __Never: Codable, Hashable {}

public protocol Policy: Codable, ConnectionPoolSource {
    
    associatedtype Configuration: Codable
    
    static var schema: String { get }
    
    var configuration: Configuration { get set }
    
    var name: String { get set }
    
    var taskAddress: NetAddress? { get set }
    
    init()
}

extension Policy {
    
    public init(stringLiteral: String) throws {
        var components = stringLiteral.components(separatedBy: ",")
        
        self.init()
        
        let l = components.removeFirst().trimmingCharacters(in: .whitespaces).components(separatedBy: "=")
        // l must be NAME = TYPE pair.
        guard l.count == 2, Self.schema == l.last?.trimmingCharacters(in: .whitespaces) else {
            throw ConfigurationSerializationError.dataCorrupted
        }
        name = l.first!.trimmingCharacters(in: .whitespaces)
        
        let json = try components.reduce(into: [:], { result, substring in
            let sequence = substring.split(separator: "=")
            guard sequence.count == 2 else {
                throw ConfigurationSerializationError.dataCorrupted
            }
            let stringLiteral = sequence[1].trimmingCharacters(in: .whitespaces)
            var value: Any
            switch stringLiteral {
                case "true":
                    value = true
                case "false":
                    value = false
                default:
                    value = Int(stringLiteral) ?? stringLiteral
            }
            result.updateValue(value, forKey: sequence[0].trimmingCharacters(in: .whitespaces))
        })
        
        let data = try JSONSerialization.data(withJSONObject: json, options: .fragmentsAllowed)
        configuration = try JSONDecoder().decode(Configuration.self, from: data)
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let stringLiteral = try container.decode(String.self)
        try self.init(stringLiteral: stringLiteral)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        
        var stringLiteral = name + " = \(Self.schema)"
        
        let data = try JSONEncoder().encode(configuration)
        let json = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed) as? [String : Any]
        json?.keys.sorted().forEach {
            let value = json![$0]!
            if let bool = value as? Bool {
                stringLiteral.append(", \($0)=\(bool ? "true" : "false")")
            } else {
                stringLiteral.append(", \($0)=\(value)")
            }
        }
        
        try container.encode(stringLiteral)
    }
}

typealias ProxyProvider = ConnectionPoolSource

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
    
    public init(stringLiteral: String) throws {
        let components = stringLiteral.components(separatedBy: ",")
        guard components.count >= 1 else {
            throw ConfigurationSerializationError.dataCorrupted
        }
        
        let type = components.first!.components(separatedBy: "=")
            .last?.trimmingCharacters(in: .whitespaces)
            .uppercased()
        
        switch type {
            case .some("DIRECT"):
                self = .direct(try DirectPolicy.init(stringLiteral: stringLiteral))
            case .some("HTTP"):
                self = .http(try HTTPProxyPolicy.init(stringLiteral: stringLiteral))
            case .some("HTTPS"):
                self = .https(try HTTPSProxyPolicy.init(stringLiteral: stringLiteral))
            case .some("REJECT"):
                self = .reject(try RejectPolicy.init(stringLiteral: stringLiteral))
            case .some("REJECT-TINYGIF"):
                self = .rejectTinyGif(try RejectTinyGifPolicy.init(stringLiteral: stringLiteral))
            case .some("SS"):
                self = .shadowsocks(try ShadowsocksPolicy.init(stringLiteral: stringLiteral))
            case .some("SOCKS5"):
                self = .socks5(try SOCKS5Policy.init(stringLiteral: stringLiteral))
            case .some("SOCKS5-TLS"):
                self = .socks5TLS(try SOCKS5OverTLSPolicy.init(stringLiteral: stringLiteral))
            case .some("VMESS"):
                self = .vmess(try VMESSPolicy.init(stringLiteral: stringLiteral))
            default:
                throw ConfigurationSerializationError.dataCorrupted
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
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let stringLiteral = try container.decode(String.self)
        try self.init(stringLiteral: stringLiteral)
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

public struct NetworkPolicy<C> {
    
    /// The protocol used by the policy.
    public let `protocol`: String
    
    /// A string containing the policy name.
    public let name: String
    
    /// An object containing the configuration for this policy.
    public var configuration: C
}

public struct DirectPolicy: Codable, Hashable, Policy {
    
    public typealias Configuration = __Never
    
    public var configuration: Configuration = .init()
    public var name: String = "DIRECT"
    public var taskAddress: NetAddress?
    public static var schema: String {
        "direct"
    }
    
    public init() {}
    
    public init(taskAddress: NetAddress?) {
        self.taskAddress = taskAddress
    }
}

public struct RejectPolicy: Codable, Hashable, Policy {
    
    public typealias Configuration = __Never
    
    public static var schema: String = "reject"

    public var configuration: Configuration = .init()

    public var name: String = "REJECT"

    public var taskAddress: NetAddress?
    
    public init() {}
    
    public init(taskAddress: NetAddress?) {
        self.taskAddress = taskAddress
    }
}

public struct RejectTinyGifPolicy: Codable, Hashable, Policy {
    
    public typealias Configuration = __Never
    
    public static var schema: String = "reject-tinygif"

    public var configuration: Configuration = .init()

    public var name: String = "REJECT-TINYGIF"

    public var taskAddress: NetAddress?
    
    public init() {}
    
    public init(taskAddress: NetAddress?) {
        self.taskAddress = taskAddress
    }
}

/// SHADOWSOCKS = ss, algorithm=chacha20-ietf-poly1305, allow-udp-relay=true, password=password, server-port=8389, server-hostname=127.0.0.1, tfo=true
public struct ShadowsocksPolicy: Codable, Hashable, Policy {
    
    public struct Configuration: Codable, Hashable {
        
        public var algorithm: String = ""
        private var codableAllowUDPRelay: Bool?
        public var allowUDPRelay: Bool {
            set { codableAllowUDPRelay = newValue }
            get { codableAllowUDPRelay ?? false }
        }
        public var password: String = ""
        public var serverHostname: String = ""
        public var serverPort: Int = 0
        private var codableIsTFOEnabled: Bool?
        public var isTFOEnabled: Bool {
            set { codableIsTFOEnabled = newValue }
            get { codableIsTFOEnabled ?? false }
        }
        
        private enum CodingKeys: String, CodingKey {
            case serverHostname = "server-hostname"
            case serverPort = "server-port"
            case password
            case algorithm
            case codableAllowUDPRelay = "allow-udp-relay"
            case codableIsTFOEnabled = "tfo"
        }
    }
    
    public static var schema: String = "ss"

    public var configuration: Configuration = .init()

    public var name: String = "ss"

    public var taskAddress: NetAddress?
    
    public init() {}
    
    public init(name: String, configuration: Configuration, taskAddress: NetAddress? = nil) {
        self.name = name
        self.configuration = configuration
        self.taskAddress = taskAddress
    }
}

/// SOCKS = socks5, password=password, server-port=8385, server-hostname=127.0.0.1, username=username
public struct SOCKS5Policy: Codable, Hashable, Policy {
    
    public struct Configuration: Codable, Hashable {
        
        public var password: String?
        public var username: String?
        public var serverHostname: String = ""
        public var serverPort: Int = 0
        
        private enum CodingKeys: String, CodingKey {
            case password
            case username
            case serverHostname = "server-hostname"
            case serverPort = "server-port"
        }
    }
    
    public static var schema: String = "socks5"

    public var configuration: Configuration = .init()

    public var name: String = "socks5"

    public var taskAddress: NetAddress?
    
    public init() {}
    
    public init(name: String, configuration: Configuration, taskAddress: NetAddress? = nil) {
        self.name = name
        self.configuration = configuration
        self.taskAddress = taskAddress
    }
}

/// SOCKS TLS = socks5-tls, password=password, server-port=443, server-hostname=socks5-tls.com, username=username
public struct SOCKS5OverTLSPolicy: Codable, Hashable, Policy {
    
    public struct Configuration: Codable, Hashable {
        
        // TODO: Allow user add client certificate.
        //        public var clientCerficateString: String?
        public var customTLSSNI: String?
        public var password: String?
        public var username: String?
        public var serverHostname: String = ""
        public var serverPort: Int = 0
        private var codableSkipCertificateVerification: Bool?
        public var skipCertificateVerification: Bool {
            set { codableSkipCertificateVerification = newValue }
            get { codableSkipCertificateVerification ?? false }
        }
        
        private enum CodingKeys: String, CodingKey {
            case customTLSSNI = "sni"
            case password
            case username
            case serverHostname = "server-hostname"
            case serverPort = "server-port"
            case codableSkipCertificateVerification = "skip-certificate-verification"
        }
        
        init() {}
    }
    
    public static var schema: String = "socks5-tls"

    public var name: String = "socks5-tls"

    public var configuration: Configuration = .init()

    public var taskAddress: NetAddress?
    
    public init() {}
    
    public init(name: String, configuration: Configuration, taskAddress: NetAddress? = nil) {
        self.name = name
        self.configuration = configuration
        self.taskAddress = taskAddress
    }
}

/// HTTP = https, password=password, server-hostname=127.0.0.1, server-port=8385, username=username
public struct HTTPProxyPolicy: Codable, Hashable, Policy {
    
    public struct Configuration: Codable, Hashable {
        
        public var password: String?
        public var username: String?
        public var serverHostname: String = ""
        public var serverPort: Int = 0
        private var codablePerformHTTPTunneling: Bool?
        public var performHTTPTunneling: Bool {
            set { codablePerformHTTPTunneling = newValue }
            get { codablePerformHTTPTunneling ?? false }
        }
        
        private enum CodingKeys: String, CodingKey {
            case password
            case username
            case serverHostname = "server-hostname"
            case serverPort = "server-port"
            case codablePerformHTTPTunneling = "always-use-connect"
        }
    }
    
    /// Name for proxy.
    public var name: String = "http"
    public var configuration: Configuration = .init()
    public var taskAddress: NetAddress?
    public static var schema: String {
        "http"
    }
    
    public init() {}
}

/// HTTPS = https, password=password, server-hostname=https.com, server-port=8385, username=username
public struct HTTPSProxyPolicy: Codable, Hashable, Policy {
    
    public struct Configuration: Codable, Hashable {
        
        // TODO: Allow user add client certificate.
        //        public var clientCerficateString: String?
        public var customTLSSNI: String?
        public var password: String?
        public var username: String?
        public var serverHostname: String = ""
        public var serverPort: Int = 0
        private var codablePerformHTTPTunneling: Bool?
        public var alwaysUseConnectTunnel: Bool {
            set { codablePerformHTTPTunneling = newValue }
            get { codablePerformHTTPTunneling ?? false }
        }
        private var codableSkipCertificateVerification: Bool?
        public var skipCertificateVerification: Bool {
            set { codableSkipCertificateVerification = newValue }
            get { codableSkipCertificateVerification ?? false }
        }
        
        private enum CodingKeys: String, CodingKey {
            case customTLSSNI = "sni"
            case password
            case username
            case serverHostname = "server-hostname"
            case serverPort = "server-port"
            case codablePerformHTTPTunneling = "always-use-connect"
            case codableSkipCertificateVerification = "skip-certificate-verification"
        }
    }
    
    public static var schema: String = "https"
    
    /// Name for proxy.
    public var name: String = "https"
    public var configuration: Configuration = .init()
    public var taskAddress: NetAddress?
    
    public init() {}
}

public struct VMESSPolicy: Codable, Hashable, Policy {
    
    public static var schema: String = "vmess"
    
    public var configuration: Configuration = .init()
    
    public var name: String = "vmess"
    
    public var taskAddress: NetAddress?
    
    public struct Configuration: Codable, Hashable {
        
        public var username: String?
        public var serverHostname: String = ""
        public var serverPort: Int = 0
        
        private enum CodingKeys: String, CodingKey {
            case username
            case serverHostname = "server-hostname"
            case serverPort = "server-port"
        }
    }
    
    public init() {}
    
    public init(name: String, configuration: Configuration, taskAddress: NetAddress? = nil) {
        self.name = name
        self.configuration = configuration
        self.taskAddress = taskAddress
    }
}

// Just a namespacing
enum Builtin {}

extension Builtin {
    
    static var policies: [ProxyPolicy] = [.direct(.init()), .reject(.init()), .rejectTinyGif(.init())]
}
