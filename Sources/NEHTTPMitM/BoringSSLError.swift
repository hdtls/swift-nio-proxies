//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_implementationOnly import CNIOBoringSSL

/// Wraps a single error from BoringSSL.
public struct BoringSSLInternalError: Equatable, CustomStringConvertible, Sendable {
  private enum Backing: Hashable {
    case boringSSLErrorInfo(UInt32, String, UInt)
    case synthetic(String)
  }

  private var backing: Backing

  private var errorMessage: String? {
    switch self.backing {
    case .boringSSLErrorInfo(let errorCode, let filepath, let line):
      // TODO(cory): This should become non-optional in the future, as it always succeeds.
      var scratchBuffer = [CChar](repeating: 0, count: 512)
      return scratchBuffer.withUnsafeMutableBufferPointer { pointer in
        CNIOBoringSSL_ERR_error_string_n(errorCode, pointer.baseAddress!, pointer.count)
        let errorString = String(cString: pointer.baseAddress!)
        return "\(errorString) at \(filepath):\(line)"
      }
    case .synthetic(let description):
      return description
    }
  }

  private var errorCode: String {
    switch self.backing {
    case .boringSSLErrorInfo(let code, _, _):
      return String(code, radix: 10)
    case .synthetic:
      return ""
    }
  }

  public var description: String {
    return "Error: \(errorCode) \(errorMessage ?? "")"
  }

  init(errorCode: UInt32, filename: String, line: UInt) {
    self.backing = .boringSSLErrorInfo(errorCode, filename, line)
  }

  private init(syntheticErrorDescription description: String) {
    self.backing = .synthetic(description)
  }

  /// Received EOF during the TLS handshake.
  public static let eofDuringHandshake = Self(syntheticErrorDescription: "EOF during handshake")

  /// Received EOF during additional certificate chain verification.
  public static let eofDuringAdditionalCertficiateChainValidation = Self(
    syntheticErrorDescription: "EOF during addition certificate chain validation"
  )
}

/// An enum that wraps individual BoringSSL errors directly.
public enum BoringSSLError: Error {
  case unknownError([BoringSSLInternalError])

  static func buildErrorStack() -> [BoringSSLInternalError] {
    var errorStack: [BoringSSLInternalError] = []

    while true {
      var file: UnsafePointer<CChar>? = nil
      var line: CInt = 0
      let errorCode = CNIOBoringSSL_ERR_get_error_line(&file, &line)
      if errorCode == 0 { break }
      let fileAsString = String(cString: file!)
      errorStack.append(
        BoringSSLInternalError(errorCode: errorCode, filename: fileAsString, line: UInt(line))
      )
    }

    return errorStack
  }
}
