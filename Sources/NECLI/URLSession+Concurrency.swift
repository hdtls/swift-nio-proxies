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

import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

extension URLSession {

  func download(for request: URLRequest) async throws -> (URL, URLResponse) {
    try await withCheckedThrowingContinuation { continuation in
      URLSession.shared.downloadTask(with: request) { url, response, error in
        guard let url = url, let response = response else {
          continuation.resume(throwing: error!)
          return
        }
        continuation.resume(returning: (url, response))
      }
      .resume()
    }
  }

  func download(from url: URL) async throws -> (URL, URLResponse) {
    try await withCheckedThrowingContinuation { continuation in
      URLSession.shared.downloadTask(with: URLRequest(url: url)) { url, response, error in
        guard let url = url, let response = response else {
          continuation.resume(throwing: error!)
          return
        }
        continuation.resume(returning: (url, response))
      }
      .resume()
    }
  }
}
