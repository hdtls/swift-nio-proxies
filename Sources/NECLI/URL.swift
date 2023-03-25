//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2023 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation

extension URL {

  static var supportDirectory: URL {
    #if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    if #available(iOS 16.0, macOS 13.0, tvOS 16.0, watchOS 9.0, *) {
      return URL.applicationSupportDirectory.appending(
        path: "io.tenbits.Netbot",
        directoryHint: .isDirectory
      )
    } else {
      let url = FileManager.default.urls(
        for: .applicationSupportDirectory,
        in: .userDomainMask
      )[0]
      return url.appendingPathComponent("io.tenbits.Netbot", isDirectory: true)
    }
    #else
    let url = FileManager.default.urls(
      for: .applicationSupportDirectory,
      in: .userDomainMask
    )[0]
    return url.appendingPathComponent("io.tenbits.Netbot", isDirectory: true)
    #endif
  }

  static var externalResourcesDirectory: URL {
    #if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    if #available(iOS 16.0, macOS 13.0, tvOS 16.0, watchOS 9.0, *) {
      return supportDirectory.appending(path: "External Resources", directoryHint: .isDirectory)
    } else {
      return supportDirectory.appendingPathComponent("External Resources", isDirectory: true)
    }
    #else
    return supportDirectory.appendingPathComponent("External Resources", isDirectory: true)
    #endif
  }
}
