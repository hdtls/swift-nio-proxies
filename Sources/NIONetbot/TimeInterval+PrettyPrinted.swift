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

import Dispatch
import Foundation

// remove when available to all platforms
#if os(Linux) || os(Windows) || os(Android) || os(OpenBSD)
extension DispatchTime {
    public func distance(to other: DispatchTime) -> DispatchTimeInterval {
        let final = other.uptimeNanoseconds
        let point = self.uptimeNanoseconds
        let duration: Int64 = Int64(
            bitPattern: final.subtractingReportingOverflow(point).partialValue
        )
        return .nanoseconds(duration >= Int.max ? Int.max : Int(duration))
    }
}

extension DispatchTimeInterval: Equatable {}
#endif

extension DispatchTimeInterval {

    public var prettyPrinted: String {
        switch self {
            case .seconds(let int):
                return "\(int) s"
            case .milliseconds(let int):
                guard int >= 1_000 else {
                    return "\(int) ms"
                }
                return "\(int / 1_000) s"
            case .microseconds(let int):
                guard int >= 1_000 else {
                    return "\(int) µs"
                }
                guard int >= 1_000_000 else {
                    return "\(int / 1_000) ms"
                }
                return "\(int / 1_000_000) s"
            case .nanoseconds(let int):
                guard int >= 1_000 else {
                    return "\(int) ns"
                }
                guard int >= 1_000_000 else {
                    return "\(int / 1_000) µs"
                }
                guard int >= 1_000_000_000 else {
                    return "\(int / 1_000_000) ms"
                }
                return "\(int / 1_000_000_000) s"
            case .never:
                return "n/a"
            #if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
                @unknown default:
                    return "n/a"
            #endif
        }
    }
}
