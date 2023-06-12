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

public enum VMESSError: Error {

  case authenticationFailure

  case operationUnsupported
}

public enum CodingError: Error {

  case typeMismatch(Any.Type, Any)

  case incorrectDataSize

  case operationUnsupported

  case failedToParseDataSize

  case failedToParseData

  case payloadTooLarge
}
