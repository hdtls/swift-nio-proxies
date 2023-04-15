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

import Foundation
import NEMisc
import NIOCore
import NIOHTTP1

extension HTTPRequestHead {

  var host: String {
    let hostField = headers.first(name: .host) ?? uri
    return hostField.components(separatedBy: ":").first ?? ""
  }

  var port: Int {
    let hostFields: [Substring] = headers.first(name: .host)?.split(separator: ":") ?? []

    var port: Int?

    if hostFields.count >= 2 {
      // Standard host field
      port = Int(hostFields[1])
    }

    if let port {
      return port
    }

    // TODO: The default port for HTTPS should be 443.
    // Port 80 if not specified
    let defaultPort = 80

    guard let portField = uri.split(separator: ":").last else {
      return defaultPort
    }
    return Int(portField) ?? defaultPort
  }
}
