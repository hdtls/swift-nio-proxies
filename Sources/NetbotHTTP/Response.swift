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

/// Represents an HTTP proxy response in an application
public struct Response: Equatable {
    
    /// The response status for the receiver.
    public var status: HTTPResponseStatus
    
    /// The version for this HTTP response.
    public var httpVersion: HTTPVersion
    
    /// The header fields for the receiver.
    public var httpHeaders: HTTPHeaders
    
    /// This data is sent as the message body of the request, as
    /// in done in an HTTP POST request.
    public var httpBody: ByteBuffer?
    
    /// Creates and initializes a HTTPProxyResponse with the given HTTPResponseHead.
    /// - Parameter head: The HTTPResponseHead for the response.
    public init(head: HTTPResponseHead) {
        self.status = head.status
        self.httpHeaders = head.headers
        self.httpVersion = head.version
    }
}

extension Response: Codable {
    
    enum CodingKeys: String, CodingKey {
        case status
        case httpVersion
        case httpHeaders
        case httpBody
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        let status = try container.decode(HTTPResponseStatus.self, forKey: .status)
        let httpVersion = try container.decode(HTTPVersion.self, forKey: .httpVersion)
        let httpHeaders = try container.decode(HTTPHeaders.self, forKey: .httpHeaders)
        let httpBody = try container.decodeIfPresent(Data.self, forKey: .httpBody)
        
        self.init(head: .init(version: httpVersion, status: status, headers: httpHeaders))
        self.httpBody = httpBody != nil ? .init(bytes: httpBody!) : nil
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(status, forKey: .status)
        try container.encode(httpVersion, forKey: .httpVersion)
        try container.encode(httpHeaders, forKey: .httpHeaders)
        try container.encodeIfPresent(httpBody != nil ? Data(Array(buffer: httpBody!)) : nil, forKey: .httpBody)
    }
}

extension HTTPResponseStatus: Codable {
    
    enum CodingKeys: String, CodingKey {
        case statusCode
        case reasonPhrase
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        let statusCode = try container.decode(Int.self, forKey: .statusCode)
        let reasonPhrase = try container.decode(String.self, forKey: .reasonPhrase)
        self.init(statusCode: statusCode, reasonPhrase: reasonPhrase)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(code, forKey: .statusCode)
        try container.encode(reasonPhrase, forKey: .reasonPhrase)
    }
}
