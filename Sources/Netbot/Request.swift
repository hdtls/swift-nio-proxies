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

import Foundation
import NIOCore
import NIOHTTP1

/// Represents an HTTP proxy request in an application.
public struct Request: Equatable {
    
    /// The id of the receiver.
    public var id: UUID
    
    /// The HTTP request method of the receiver.
    public var httpMethod: HTTPMethod
    
    /// The URL of the receiver.
    public var url: URL?
    
    /// The version for this HTTP request.
    public var httpVersion: HTTPVersion
    
    /// The header fields of the receiver.
    public var httpHeaders: HTTPHeaders
    
    /// This data is sent as the message body of the request, as
    /// in done in an HTTP POST request.
    public var httpBody: ByteBuffer?
    
    /// Creates and initializes a `Request` with specified id and head.
    /// - Parameter head: The HTTPRequestHead for the request.
    public init(id: UUID, head: HTTPRequestHead) {
        self.id = id
        self.httpMethod = head.method
        self.url = URL(string: head.uri)
        self.httpVersion = head.version
        self.httpHeaders = head.headers
    }
    
    /// Initialize an instance of `Request` with specified head.
    /// - Parameter head: The HTTPRequestHead for the request.
    ///
    /// Calling this method is equivalent to calling `init(id:head:)` with `UUID()` id and specified head.
    public init(head: HTTPRequestHead) {
        self.init(id: UUID(), head: head)
    }
}

extension Request: Codable {
    
    enum CodingKeys: String, CodingKey {
        case id
        case url
        case httpMethod
        case httpVersion
        case httpBody
        case httpHeaders
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        let id = try container.decode(UUID.self, forKey: .id)
        let url = try container.decode(URL.self, forKey: .url)
        let httpHeaders = try container.decode(HTTPHeaders.self, forKey: .httpHeaders)
        let httpVersion = try container.decode(HTTPVersion.self, forKey: .httpVersion)
        let httpMethod = try container.decode(String.self, forKey: .httpMethod)
        let httpBody = try container.decodeIfPresent(Data.self, forKey: .httpBody)
        
        self.init(id: id, head: .init(
            version: httpVersion,
            method: .init(rawValue: httpMethod),
            uri: url.absoluteString,
            headers: httpHeaders
        ))
        
        self.httpBody = httpBody != nil ? .init(bytes: httpBody!) : nil
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(id, forKey: .id)
        try container.encode(url, forKey: .url)
        try container.encode(httpHeaders, forKey: .httpHeaders)
        try container.encode(httpVersion, forKey: .httpVersion)
        try container.encode(httpMethod.rawValue, forKey: .httpMethod)
        try container.encodeIfPresent(httpBody != nil ? Data(Array(buffer: httpBody!)) : nil, forKey: .httpBody)
    }
}

extension HTTPHeaders: Codable {
    
    public init(from decoder: Decoder) throws {
        var container = try decoder.unkeyedContainer()
        
        var dictionaryLiteral: [(String, String)] = []
        
        while !container.isAtEnd {
            let element = try container.decode(String.self)
            let components = element.components(separatedBy: ": ")
            dictionaryLiteral.append((components[0], components[1]))
        }
        
        self.init(dictionaryLiteral)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.unkeyedContainer()
        try self.forEach { (name: String, value: String) in
            try container.encode(name + ": " + value)
        }
    }
}

extension HTTPVersion: Codable {
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        
        let httpVersion = try container.decode(String.self).split(separator: ".")
        
        self.init(major: Int(httpVersion[0])!, minor: Int(httpVersion[1])!)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        
        try container.encode("\(major).\(minor)")
    }
}
