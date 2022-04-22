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

@_implementationOnly import CMaxMindDB
import Foundation

public struct CMaxMindDBError: CustomStringConvertible {

    public let errorCode: Int32

    init(errorCode: Int32) {
        self.errorCode = errorCode
    }

    public var description: String {
        String(cString: MMDB_strerror(errorCode))
    }
}

public struct GetaddrinfoError: CustomStringConvertible {

    public let errorCode: Int32

    init(errorCode: Int32) {
        self.errorCode = errorCode
    }

    public var description: String {
        String(cString: gai_strerror(errorCode))
    }
}

public enum MaxMindDBError: Error {
    case unknowError(CMaxMindDBError)
    case gaiError(GetaddrinfoError)
}
