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

import ArgumentParser
import Foundation
import NECLICore

//@main
struct CLI: AsyncParsableCommand {

  /// The SOCKS5 proxy server listen address.
  @Option(help: "The SOCKS5 proxy server listen address.")
  public var socksListenAddress: String?

  /// The SOCKS5 proxy server listen port.
  @Option(help: "The SOCKS5 proxy server listen port.")
  public var socksListenPort: Int?

  /// The web and secure web proxy server listen address.
  @Option(help: "The web and secure web proxy server listen address.")
  public var httpListenAddress: String?

  /// The web and secure web proxy server listen port.
  @Option(help: "The web and secure web proxy server listen port.")
  public var httpListenPort: Int?

  /// The proxy configuration file path.
  @Option(name: .shortAndLong, help: "The proxy profile file.")
  public var profileFile: String?

  /// The log level for logger.
  ///
  /// Has higher priority than the loglevel defined in the profile file.
  @Option(help: "The log level for logger.")
  public var logLevel: Logger.Level?

  /// The proxy outbound mode.
  @Option(help: "The proxy outbound mode.")
  public var outboundMode: OutboundMode = .direct

  /// A boolean value that determines whether http capture should be enabled.
  @Flag(help: "Enable HTTP capture, should be enabled only when needed.")
  public var enableHTTPCapture: Bool = false

  /// A boolean value that determines whether MitM should be enabled.
  @Flag(help: "Enable MitM, should be enabled only when needed.")
  public var enableMitm: Bool = false

  func run() async throws {
    var profile: Profile = .init()

    if let path = profileFile {
      let data = try Data(contentsOf: URL(fileURLWithPath: path))
      let jsonObject = try ProfileSerialization.jsonObject(with: data)
      let jsonData = try JSONSerialization.data(
        withJSONObject: jsonObject,
        options: .fragmentsAllowed
      )
      let jsonDecoder = JSONDecoder()
      profile = try jsonDecoder.decode(Profile.self, from: jsonData)
    }

    //        let externalResourcesDirectory: URL = {
    //            var url = FileManager.default.urls(
    //                for: .applicationSupportDirectory,
    //                in: .userDomainMask
    //            )[0]
    //            url.appendPathComponent("io.tenbits.Netbot")
    //            return url.appendingPathComponent("External Resources")
    //        }()
    //
    //        let rules: [ParsableRule] = profile.rules.map {
    //            guard var resources = $0 as? ExternalRuleResources & ParsableRule else {
    //                return $0
    //            }
    //
    //            resources.loadAllRules(
    //                from: externalResourcesDirectory.appendingPathComponent(
    //                    resources.externalResourcesStorageName
    //                )
    //            )
    //            return resources
    //        }
    //        profile.rules = rules

    let encoder = JSONEncoder()
    encoder.outputFormatting = .prettyPrinted

    let data = try encoder.encode(profile)
    try (data as NSData).write(
      toFile: "/Users/Paul/Developer/swift/swift-nio-netbot/Netbot.json"
    )
    print(profile)
  }
}
