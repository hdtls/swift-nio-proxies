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
import NIOConcurrencyHelpers
import NIOCore
import NIOPosix

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public class DNSOverHTTPSResolver: NIOPosix.Resolver {

    private let url: URL
    private let v4Future: EventLoopPromise<[SocketAddress]>
    private let v6Future: EventLoopPromise<[SocketAddress]>
    private var tasks: [String: Task<(Data, URLResponse), Error>] = [:]
    private let session: URLSession = URLSession(configuration: .default)
    private let lock = Lock()

    /// Create a new resolver.
    ///
    /// - Parameter eventLoop: The `EventLoop` whose thread this resolver will block.
    public init(url: URL, eventLoop: EventLoop) {
        self.url = url
        self.v4Future = eventLoop.makePromise()
        self.v6Future = eventLoop.makePromise()
    }

    public func initiateAQuery(host: String, port: Int) -> EventLoopFuture<[SocketAddress]> {
        v4Future.completeWithTask {
            self.lock.lock()
            defer { self.lock.unlock() }

            return try await self.initiateAQuery(host: host, port: port)
        }
        return v4Future.futureResult
    }

    public func initiateAQuery(host: String, port: Int) async throws -> [SocketAddress] {
        try await initialeQuery(host: host, port: port, type: 1)
    }

    public func initiateAAAAQuery(host: String, port: Int) -> EventLoopFuture<[SocketAddress]> {
        v6Future.completeWithTask {
            self.lock.lock()
            defer { self.lock.unlock() }

            return try await self.initialeAAAAQuery(host: host, port: port)
        }
        return v6Future.futureResult
    }

    public func initialeAAAAQuery(host: String, port: Int) async throws -> [SocketAddress] {
        try await initialeQuery(host: host, port: port, type: 28)
    }

    private func initialeQuery(host: String, port: Int, type: UInt16) async throws
        -> [SocketAddress]
    {
        let task: Task<(Data, URLResponse), Error>
        if let t = self.tasks[host], !t.isCancelled {
            task = t
        } else {
            task = Task {
                let options: Message.Options = [.standardQuery, .recursionDesired]

                var buffer = ByteBuffer()
                buffer.writeInteger(Message.ID.next())
                buffer.writeInteger(options.rawValue)
                buffer.writeInteger(UInt16(1))
                buffer.writeInteger(UInt16.zero)
                buffer.writeInteger(UInt16.zero)
                buffer.writeInteger(UInt16.zero)
                host.split(separator: ".").forEach { label in
                    buffer.writeInteger(UInt8(label.utf8.count))
                    buffer.writeBytes(Array(label.utf8))
                }
                buffer.writeInteger(UInt8.zero)
                buffer.writeInteger(type)
                buffer.writeInteger(Question.Class.internet.rawValue)

                var urlRequest = URLRequest(url: self.url)
                urlRequest.httpMethod = "POST"
                urlRequest.allHTTPHeaderFields = [
                    "Accept": "application/dns-message",
                    "Content-Type": "application/dns-message",
                    "Content-Length": "\(buffer.readableBytes)",
                ]
                urlRequest.httpBody = Data(buffer.readBytes(length: buffer.readableBytes)!)

                return try await withCheckedThrowingContinuation {
                    continuation in
                    self.session.dataTask(with: urlRequest) { data, response, error in
                        guard error == nil else {
                            continuation.resume(throwing: error!)
                            return
                        }

                        continuation.resume(returning: (data!, response!))
                    }.resume()
                }
            }
        }

        self.tasks[host] = task

        let (data, _) = try await task.value

        let message = try MessageParser(buffer: ByteBuffer(bytes: data)).parse()

        return try message.answers.filter { $0.recordType == 1 }.map { answer in
            try SocketAddress(packedIPAddress: ByteBuffer(bytes: answer.resource), port: port)
        }
    }

    public func cancelQueries() {
        self.lock.withLockVoid {
            self.tasks.values.forEach {
                if !$0.isCancelled {
                    $0.cancel()
                }
            }
            self.tasks.removeAll()
        }
    }
}
