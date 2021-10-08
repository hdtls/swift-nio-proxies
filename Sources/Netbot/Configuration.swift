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

import ArgumentParser
import HTTP
import Foundation

class Parser {
    /// Represents a `KEY=VALUE` pair in a dotenv file.
    private struct Line: Equatable {
        /// The key.
        let key: String
        
        /// The value.
        let value: String
    }
    
    private var source: ByteBuffer
    
    private var head: String = ""
    
    private init(source: ByteBuffer) {
        self.source = source
    }
    
    /// Parse configuration file to json.
    /// - Returns: JSON encoded object.
    static func jsonObject(with data: Data) -> Any {
        var json: [String : Any] = [:]
        let parser = Parser.init(source: .init(bytes: data))
        
        while let next = parser.parseNext() {
            guard let line = next as? Line else {
                parser.head = (next as! String).trimmingCharacters(in: .whitespaces)
                continue
            }
            
            var actual: Any
            // Transfer "true, false" to Bool value.
            let value = line.value.trimmingCharacters(in: .whitespaces)
            switch value {
                case "true":
                    actual = true
                case "false":
                    actual = false
                default:
                    actual = value
            }
            
            if parser.head == Configuration.CodingKeys.ruleField.rawValue {
                var rules: [Any] = (json[parser.head] as? [Any]) ?? []
                rules.append(actual)
                json[parser.head] = rules
            } else {
                var dictionary: [String : Any] = (json[parser.head] as? [String : Any]) ?? [:]
                dictionary[line.key.trimmingCharacters(in: .whitespaces)] = actual
                json[parser.head] = dictionary
            }
        }
        
        return json
    }
    
    private func parseNext() -> Any? {
        self.skipSpaces()
        guard let peek = self.peek() else {
            return nil
        }
        switch peek {
            case .octothorpe, .semicolon:
                // comment following, skip it
                self.skipComment()
                // then parse next
                return self.parseNext()
            case .leftSquareBracket:
                self.pop()
                return self.parseLineHead()
            case .newLine:
                // empty line, skip
                self.pop() // \n
                           // then parse next
                return self.parseNext()
            default:
                // this is a valid line, parse it
                guard self.head == Configuration.CodingKeys.ruleField.rawValue else {
                    return self.parseLine()
                }
                guard let value = self.parseLineValue() else {
                    return nil
                }
                return Line(key: "", value: value)
        }
    }
    
    private func skipComment() {
        let commentLength: Int
        if let toNewLine = self.countDistance(to: .newLine) {
            commentLength = toNewLine + 1 // include newline
        } else {
            commentLength = self.source.readableBytes
        }
        self.source.moveReaderIndex(forwardBy: commentLength)
    }
    
    private func parseLineHead() -> String? {
        guard let headLength = self.countDistance(to: .rightSquareBracket) else {
            return nil
        }
        guard let head = self.source.readString(length: headLength) else {
            return nil
        }
        self.pop() // ]
        
        return head
    }
    
    private func parseLine() -> Line? {
        guard let keyLength = self.countDistance(to: .equal) else {
            return nil
        }
        guard let key = self.source.readString(length: keyLength) else {
            return nil
        }
        self.pop() // =
        guard let value = self.parseLineValue() else {
            return nil
        }
        return Line(key: key, value: value)
    }
    
    private func parseLineValue() -> String? {
        let valueLength: Int
        if let toNewLine = self.countDistance(to: .newLine) {
            valueLength = toNewLine
        } else {
            valueLength = self.source.readableBytes
        }
        guard let value = self.source.readString(length: valueLength) else {
            return nil
        }
        guard let first = value.first, let last = value.last else {
            return value
        }
        // check for quoted strings
        switch (first, last) {
            case ("\"", "\""):
                // double quoted strings support escaped \n
                return value.dropFirst().dropLast()
                    .replacingOccurrences(of: "\\n", with: "\n")
            case ("'", "'"):
                // single quoted strings just need quotes removed
                return value.dropFirst().dropLast() + ""
            default: return value
        }
    }
    
    private func skipSpaces() {
    scan: while let next = self.peek() {
        switch next {
            case .space: self.pop()
            default: break scan
        }
    }
    }
    
    private func peek() -> UInt8? {
        return self.source.getInteger(at: self.source.readerIndex)
    }
    
    private func pop() {
        self.source.moveReaderIndex(forwardBy: 1)
    }
    
    private func countDistance(to byte: UInt8) -> Int? {
        var copy = self.source
        var found = false
    scan: while let next = copy.readInteger(as: UInt8.self) {
        if next == byte {
            found = true
            break scan
        }
    }
        guard found else {
            return nil
        }
        let distance = copy.readerIndex - source.readerIndex
        guard distance != 0 else {
            return nil
        }
        return distance - 1
    }
}

extension UInt8 {
    fileprivate static var newLine: UInt8 {
        return 0xA
    }
    
    fileprivate static var space: UInt8 {
        return 0x20
    }
    
    fileprivate static var octothorpe: UInt8 {
        return 0x23
    }
    
    fileprivate static var semicolon: UInt8 {
        return 0x3b
    }
    
    fileprivate static var equal: UInt8 {
        return 0x3D
    }
    
    fileprivate static var leftSquareBracket: UInt8 {
        return 0x5b
    }
    
    fileprivate static var rightSquareBracket: UInt8 {
        return 0x5d
    }
}

public struct Configuration: Codable {
    
    var ruleField: [Rule]
    var mitmField: MitM.Configuration
    var generalField: BasicConfiguration
    var replicaField: ReplicaConfiguration
    
    enum CodingKeys: String, CodingKey {
        case ruleField = "Rule"
        case mitmField = "MitM"
        case generalField = "General"
        case replicaField = "Replica"
    }
    
    public init() {
        ruleField = .init()
        mitmField = .init()
        generalField = .init()
        replicaField = .init()
    }
    
    public init(from decoder: Decoder) throws {
        let keyedContainer = try decoder.container(keyedBy: CodingKeys.self)
        ruleField = try keyedContainer.decodeIfPresent([Rule].self, forKey: .ruleField) ?? .init()
        mitmField = try keyedContainer.decodeIfPresent(MitM.Configuration.self, forKey: .mitmField) ?? .init()
        generalField = try keyedContainer.decodeIfPresent(BasicConfiguration.self, forKey: .generalField) ?? .init()
        replicaField = try keyedContainer.decodeIfPresent(ReplicaConfiguration.self, forKey: .replicaField) ?? .init()
    }
    
    //    public func encode(to encoder: Encoder) throws {
    //        var keyedContainer = encoder.container(keyedBy: CodingKeys.self)
    //        keyedContainer.encode(ruleField, forKey: .ruleField)
    //        keyedContainer.encode(mitmField, forKey: .mitmField)
    //        keyedContainer.encode(generalField, forKey: .generalField)
    //        keyedContainer.encode(replicaField, forKey: .replicaField)
    //    }
}

public enum DecodingError: Error {
    case invalidConfFile(line: Int)
    
    case ruleValidationFailed(reason: RuleValidationFailureReason)
    case dataCorrupted(String)
    case valueNotFound(String)
    
    public enum RuleValidationFailureReason {
        case invalidRuleStringLiteral
        case unacceptableRuleType
    }
}

public struct BasicConfiguration: Codable, Equatable {
    
    public var logLevel: Logger.Level
    public var dnsServers: [String]
    public var skipProxy: [String]?
    public var httpListenAddress: String?
    public var httpListenPort: Int?
    public var socksListenAddress: String?
    public var socksListenPort: Int?
    public var excludeSimpleHostnames: Bool
    
    enum CodingKeys: String, CodingKey {
        case logLevel = "log-level"
        case dnsServers = "dns-servers"
        case skipProxy = "skip-proxy"
        case httpListenAddress = "http-listen-address"
        case httpListenPort = "http-listen-port"
        case socksListenAddress = "socks-listen-address"
        case socksListenPort = "socks-listen-port"
        case excludeSimpleHostnames = "exclude-simple-hostnames"
    }
    
    public init(logLevel: Logger.Level = .info,
                dnsServers: [String] = ["system"],
                skipProxy: [String]? = nil,
                httpListenAddress: String? = nil,
                httpListenPort: Int? = nil,
                socksListenAddress: String? = nil,
                socksListenPort: Int? = nil,
                excludeSimpleHostnames: Bool = false) {
        self.logLevel = logLevel
        self.dnsServers = dnsServers
        self.skipProxy = skipProxy
        self.httpListenAddress = httpListenAddress
        self.httpListenPort = httpListenPort
        self.socksListenAddress = socksListenAddress
        self.socksListenPort = socksListenPort
        self.excludeSimpleHostnames = excludeSimpleHostnames
    }
    
    public init(from decoder: Decoder) throws {
        let keyedContainer = try decoder.container(keyedBy: CodingKeys.self)
        logLevel = try keyedContainer.decodeIfPresent(Logger.Level.self, forKey: .logLevel) ?? .info
        dnsServers = try keyedContainer.decodeIfPresent(String.self, forKey: .dnsServers)?.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces )} ?? ["system"]
        skipProxy = try keyedContainer.decodeIfPresent(String.self, forKey: .skipProxy)?.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces )}
        httpListenAddress = try keyedContainer.decodeIfPresent(String.self, forKey: .httpListenAddress)
        httpListenPort = Int(try keyedContainer.decodeIfPresent(String.self, forKey: .httpListenPort) ?? "")
        socksListenAddress = try keyedContainer.decodeIfPresent(String.self, forKey: .socksListenAddress)
        socksListenPort = Int(try keyedContainer.decodeIfPresent(String.self, forKey: .socksListenPort) ?? "")
        excludeSimpleHostnames = try keyedContainer.decodeIfPresent(Bool.self, forKey: .excludeSimpleHostnames) ?? false
    }
    
    public func encode(to encoder: Encoder) throws {
        var keyedContainer = encoder.container(keyedBy: CodingKeys.self)
        try keyedContainer.encode(logLevel, forKey: .logLevel)
        try keyedContainer.encode(dnsServers.joined(separator: ","), forKey: .dnsServers)
        try keyedContainer.encodeIfPresent(skipProxy?.joined(separator: ","), forKey: .skipProxy)
        try keyedContainer.encodeIfPresent(httpListenAddress, forKey: .httpListenAddress)
        try keyedContainer.encodeIfPresent(httpListenPort != nil ? "\(httpListenPort!)" : nil, forKey: .httpListenPort)
        try keyedContainer.encodeIfPresent(socksListenAddress, forKey: .socksListenAddress)
        try keyedContainer.encodeIfPresent(socksListenPort != nil ? "\(socksListenPort!)" : nil, forKey: .socksListenPort)
        try keyedContainer.encodeIfPresent(excludeSimpleHostnames, forKey: .excludeSimpleHostnames)
    }
}

public struct ReplicaConfiguration: Codable, Equatable {
    
    public var hideAppleRequests: Bool
    public var hideCrashlyticsRequests: Bool
    public var hideCrashReporterRequests: Bool
    public var hideUDP: Bool
    public var reqMsgFilterType: String?
    public var reqMsgFilter: String?
    
    enum CodingKeys: String, CodingKey {
        case hideAppleRequests = "hide-apple-requests"
        case hideCrashlyticsRequests = "hide-crashlytics-requests"
        case hideCrashReporterRequests = "hide-crash-reporter-requests"
        case hideUDP = "hide-udp"
        case reqMsgFilterType = "req-msg-filter-type"
        case reqMsgFilter = "req-msg-filter"
    }
    
    public init(hideAppleRequests: Bool = false,
                hideCrashlyticsRequests: Bool = false,
                hideCrashReporterRequests: Bool = false,
                hideUDP: Bool = false,
                reqMsgFilterType: String? = nil,
                reqMsgFilter: String? = nil) {
        self.hideAppleRequests = hideAppleRequests
        self.hideCrashlyticsRequests = hideCrashlyticsRequests
        self.hideCrashReporterRequests = hideCrashReporterRequests
        self.hideUDP = hideUDP
        self.reqMsgFilterType = reqMsgFilterType
        self.reqMsgFilter = reqMsgFilter
    }
    
    public init(from decoder: Decoder) throws {
        let keyedContainer = try decoder.container(keyedBy: CodingKeys.self)
        hideAppleRequests = try keyedContainer.decodeIfPresent(Bool.self, forKey: .hideAppleRequests) ?? false
        hideCrashlyticsRequests = try keyedContainer.decodeIfPresent(Bool.self, forKey: .hideCrashlyticsRequests) ?? false
        hideCrashReporterRequests = try keyedContainer.decodeIfPresent(Bool.self, forKey: .hideCrashReporterRequests) ?? false
        hideUDP = try keyedContainer.decodeIfPresent(Bool.self, forKey: .hideUDP) ?? false
        reqMsgFilter = try keyedContainer.decodeIfPresent(String.self, forKey: .reqMsgFilter)
        reqMsgFilterType = try keyedContainer.decodeIfPresent(String.self, forKey: .reqMsgFilterType)
    }
    
    public func encode(to encoder: Encoder) throws {
        var keyedContainer = encoder.container(keyedBy: CodingKeys.self)
        try keyedContainer.encode(hideAppleRequests, forKey: .hideAppleRequests)
        try keyedContainer.encode(hideCrashlyticsRequests, forKey: .hideCrashlyticsRequests)
        try keyedContainer.encode(hideCrashReporterRequests, forKey: .hideCrashReporterRequests)
        try keyedContainer.encode(hideUDP, forKey: .hideUDP)
        try keyedContainer.encodeIfPresent(reqMsgFilter, forKey: .reqMsgFilter)
        try keyedContainer.encodeIfPresent(reqMsgFilterType, forKey: .reqMsgFilterType)
    }
}

public enum RuleType: String {
    case domain = "DOMAIN"
    case domainSuffix = "DOMAIN-SUFFIX"
    case domainKeyword = "DOMAIN-KEYWORD"
    case domainSet = "DOMAIN-SET"
    case final = "FINAL"
    case geoip = "GEOIP"
    case ipcidr = "IP-CIDR"
    case processName = "PROCESS-NAME"
    case ruleSet = "RULE-SET"
}

public struct Rule: Codable, Equatable {
    
    public var type: RuleType
    public var pattern: String?
    public var policy: String
    public var comment: String?
    
    init(string: String) throws {
        let parts = string.split(separator: ",").map(String.init)
        guard parts.count >= 2 else {
            throw DecodingError.ruleValidationFailed(reason: .invalidRuleStringLiteral)
        }
        
        guard let t = RuleType(rawValue: parts.first!.trimmingCharacters(in: .whitespaces)) else {
            throw DecodingError.ruleValidationFailed(reason: .unacceptableRuleType)
        }
        
        type = t
        
        if t == .final {
            if parts[1].contains("//") {
                let splited = parts[1].components(separatedBy: "//")
                policy = splited.first!.trimmingCharacters(in: .whitespaces)
                comment = splited.last!.trimmingCharacters(in: .whitespaces)
            } else {
                policy = parts[1].trimmingCharacters(in: .whitespaces)
            }
        } else {
            guard parts.count >= 3 else {
                throw DecodingError.ruleValidationFailed(reason: .invalidRuleStringLiteral)
            }
            pattern = parts[1].trimmingCharacters(in: .whitespaces)
            if parts[2].contains("//") {
                let splited = parts[2].components(separatedBy: "//")
                policy = splited.first!.trimmingCharacters(in: .whitespaces)
                comment = splited.last!.trimmingCharacters(in: .whitespaces)
            } else {
                policy = parts[2].trimmingCharacters(in: .whitespaces)
            }
        }
    }
    
    public init(from decoder: Decoder) throws {
        let singleValueContainer = try decoder.singleValueContainer()
        let stringLiteral = try singleValueContainer.decode(String.self)
        try self.init(string: stringLiteral)
    }
    
    public func encode(to encoder: Encoder) throws {
        var singleValueContainer = encoder.singleValueContainer()
        let stringLiteral = "\(type.rawValue),\(pattern != nil ? pattern! + "," : "")\(policy)\(comment != nil ? " // \(comment!)" : "")"
        try singleValueContainer.encode(stringLiteral)
    }
}
