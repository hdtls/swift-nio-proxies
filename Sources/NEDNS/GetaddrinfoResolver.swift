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

//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// THIS FILE IS MOSTLY COPIED FROM [swift-nio](https://github.com/apple/swift-nio)

import Dispatch
@_exported import NIOCore
import NIOPosix

extension NIOBSDSocket {
  /// Specifies the type of socket.
  public struct SocketType: RawRepresentable {
    public typealias RawValue = CInt
    public var rawValue: RawValue
    public init(rawValue: RawValue) {
      self.rawValue = rawValue
    }
  }
}

// Socket Types
extension NIOBSDSocket.SocketType {
  /// Supports datagrams, which are connectionless, unreliable messages of a
  /// fixed (typically small) maximum length.
  #if os(Linux)
  public static let datagram: NIOBSDSocket.SocketType =
    NIOBSDSocket.SocketType(rawValue: CInt(SOCK_DGRAM.rawValue))
  #else
  public static let datagram: NIOBSDSocket.SocketType =
    NIOBSDSocket.SocketType(rawValue: SOCK_DGRAM)
  #endif

  /// Supports reliable, two-way, connection-based byte streams without
  /// duplication of data and without preservation of boundaries.
  #if os(Linux)
  public static let stream: NIOBSDSocket.SocketType =
    NIOBSDSocket.SocketType(rawValue: CInt(SOCK_STREAM.rawValue))
  #else
  public static let stream: NIOBSDSocket.SocketType =
    NIOBSDSocket.SocketType(rawValue: SOCK_STREAM)
  #endif
}

#if os(Linux) || os(FreeBSD) || os(Android)
import CNIOLinux
#endif

#if os(Windows)
import let WinSDK.AF_INET
import let WinSDK.AF_INET6

import func WinSDK.FreeAddrInfoW
import func WinSDK.GetAddrInfoW
import func WinSDK.gai_strerrorA

import struct WinSDK.ADDRESS_FAMILY
import struct WinSDK.ADDRINFOW
import struct WinSDK.SOCKADDR_IN
import struct WinSDK.SOCKADDR_IN6
#endif

// A thread-specific variable where we store the offload queue if we're on an `SelectableEventLoop`.
let offloadQueueTSV = ThreadSpecificVariable<DispatchQueue>()

/// A DNS resolver built on top of the libc `getaddrinfo` function.
///
/// This is the lowest-common-denominator resolver available to NIO. It's not really a very good
/// solution because the `getaddrinfo` call blocks during the DNS resolution, meaning that this resolver
/// will block a thread for as long as it takes to perform the getaddrinfo call. To prevent it from blocking `EventLoop`
/// threads, it will offload the blocking `getaddrinfo` calls to a `DispatchQueue`.
/// One advantage from leveraging `getaddrinfo` is the automatic conformance to RFC 6724, which removes some of the work
/// needed to implement it.
///
/// This resolver is a single-use object: it can only be used to perform a single host resolution.
final public class GetaddrinfoResolver: Resolver {
  private let v4Future: EventLoopPromise<[SocketAddress]>
  private let v6Future: EventLoopPromise<[SocketAddress]>
  private let aiSocktype: NIOBSDSocket.SocketType
  private let aiProtocol: NIOBSDSocket.OptionLevel

  /// Create a new resolver.
  ///
  /// - parameters:
  ///     - loop: The `EventLoop` whose thread this resolver will block.
  ///     - aiSocktype: The sock type to use as hint when calling getaddrinfo.
  ///     - aiProtocol: the protocol to use as hint when calling getaddrinfo.
  public init(
    eventLoop: EventLoop,
    aiSocktype: NIOBSDSocket.SocketType = .stream,
    aiProtocol: NIOBSDSocket.OptionLevel = .init(rawValue: CInt(IPPROTO_TCP))
  ) {
    self.v4Future = eventLoop.makePromise()
    self.v6Future = eventLoop.makePromise()
    self.aiSocktype = aiSocktype
    self.aiProtocol = aiProtocol
  }

  /// Initiate a DNS A query for a given host.
  ///
  /// Due to the nature of `getaddrinfo`, we only actually call the function once, in the AAAA query.
  /// That means this just returns the future for the A results, which in practice will always have been
  /// satisfied by the time this function is called.
  ///
  /// - parameters:
  ///     - host: The hostname to do an A lookup on.
  ///     - port: The port we'll be connecting to.
  /// - returns: An `EventLoopFuture` that fires with the result of the lookup.
  public func initiateAQuery(host: String, port: Int) -> EventLoopFuture<[SocketAddress]> {
    return v4Future.futureResult
  }

  /// Initiate a DNS AAAA query for a given host.
  ///
  /// Due to the nature of `getaddrinfo`, we only actually call the function once, in this function.
  /// That means this function call actually blocks: sorry!
  ///
  /// - parameters:
  ///     - host: The hostname to do an AAAA lookup on.
  ///     - port: The port we'll be connecting to.
  /// - returns: An `EventLoopFuture` that fires with the result of the lookup.
  public func initiateAAAAQuery(host: String, port: Int) -> EventLoopFuture<[SocketAddress]> {
    self.offloadQueue().async {
      self.resolveBlocking(host: host, port: port)
    }
    return v6Future.futureResult
  }

  private func offloadQueue() -> DispatchQueue {
    if let offloadQueue = offloadQueueTSV.currentValue {
      return offloadQueue
    } else {
      if MultiThreadedEventLoopGroup.currentEventLoop != nil {
        // Okay, we're on an SelectableEL thread. Let's stuff our queue into the thread local.
        let offloadQueue = DispatchQueue(
          label: "io.swiftnio.GetaddrinfoResolver.offloadQueue"
        )
        offloadQueueTSV.currentValue = offloadQueue
        return offloadQueue
      } else {
        return DispatchQueue.global()
      }
    }
  }

  /// Cancel all outstanding DNS queries.
  ///
  /// This method is called whenever queries that have not completed no longer have their
  /// results needed. The resolver should, if possible, abort any outstanding queries and
  /// clean up their state.
  ///
  /// In the getaddrinfo case this is a no-op, as the resolver blocks.
  public func cancelQueries() {}

  /// Perform the DNS queries and record the result.
  ///
  /// - parameters:
  ///     - host: The hostname to do the DNS queries on.
  ///     - port: The port we'll be connecting to.
  private func resolveBlocking(host: String, port: Int) {
    #if os(Windows)
    host.withCString(encodedAs: UTF16.self) { wszHost in
      String(port).withCString(encodedAs: UTF16.self) { wszPort in
        var pResult: UnsafeMutablePointer<ADDRINFOW>?

        var aiHints: ADDRINFOW = ADDRINFOW()
        aiHints.ai_socktype = self.aiSocktype.rawValue
        aiHints.ai_protocol = self.aiProtocol.rawValue

        let iResult = GetAddrInfoW(wszHost, wszPort, &aiHints, &pResult)
        guard iResult == 0 else {
          self.fail(SocketAddressError.unknown(host: host, port: port))
          return
        }

        if let pResult = pResult {
          self.parseAndPublishResults(pResult, host: host)
          FreeAddrInfoW(pResult)
        } else {
          self.fail(SocketAddressError.unsupported)
        }
      }
    }
    #else
    var info: UnsafeMutablePointer<addrinfo>?

    var hint = addrinfo()
    hint.ai_socktype = self.aiSocktype.rawValue
    hint.ai_protocol = self.aiProtocol.rawValue
    guard getaddrinfo(host, String(port), &hint, &info) == 0 else {
      self.fail(SocketAddressError.unknown(host: host, port: port))
      return
    }

    if let info = info {
      self.parseAndPublishResults(info, host: host)
      freeaddrinfo(info)
    } else {
      // this is odd, getaddrinfo returned NULL
      self.fail(SocketAddressError.unsupported)
    }
    #endif
  }

  /// Parses the DNS results from the `addrinfo` linked list.
  ///
  /// - parameters:
  ///     - info: The pointer to the first of the `addrinfo` structures in the list.
  ///     - host: The hostname we resolved.
  #if os(Windows)
  internal typealias CAddrInfo = ADDRINFOW
  #else
  internal typealias CAddrInfo = addrinfo
  #endif

  private func parseAndPublishResults(_ info: UnsafeMutablePointer<CAddrInfo>, host: String) {
    var v4Results: [SocketAddress] = []
    var v6Results: [SocketAddress] = []

    var info: UnsafeMutablePointer<CAddrInfo> = info
    while true {
      let addressBytes = UnsafeRawPointer(info.pointee.ai_addr)
      switch NIOBSDSocket.AddressFamily(rawValue: info.pointee.ai_family) {
      case .inet:
        // Force-unwrap must be safe, or libc did the wrong thing.
        v4Results.append(.init(addressBytes!.load(as: sockaddr_in.self), host: host))
      case .inet6:
        // Force-unwrap must be safe, or libc did the wrong thing.
        v6Results.append(.init(addressBytes!.load(as: sockaddr_in6.self), host: host))
      default:
        self.fail(SocketAddressError.unsupported)
        return
      }

      guard let nextInfo = info.pointee.ai_next else {
        break
      }

      info = nextInfo
    }

    v6Future.succeed(v6Results)
    v4Future.succeed(v4Results)
  }

  /// Record an error and fail the lookup process.
  ///
  /// - parameters:
  ///     - error: The error encountered during lookup.
  private func fail(_ error: Error) {
    self.v6Future.fail(error)
    self.v4Future.fail(error)
  }
}

#if swift(>=5.7)
extension NIOBSDSocket.SocketType: Sendable {}

extension GetaddrinfoResolver: Sendable {}
#endif
