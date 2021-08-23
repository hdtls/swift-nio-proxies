//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright © 2019 Netbot Ltd. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

enum SecurityError: Error, Equatable {

    enum SecuritySetupFailureReason {
        case invalidIV
        case invalidKey
        case invalidData
    }

    enum ResponseValidationFailureReason {
        case invalidLength
    }

    case securityNotAvailable
    case missingALGO(algorithm: Algorithm)
    case securitySetupFailed(reason: SecuritySetupFailureReason)
    case responseValidationFailed(reason: ResponseValidationFailureReason)
}
