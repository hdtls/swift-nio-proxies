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
import Logging
import NECLICore

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

@main
public struct NetbotCLITool: AsyncParsableCommand {

  /// A configuration object use for config this command.
  public static var configuration: CommandConfiguration = .init(
    commandName: "netbotcli",
    abstract: "",
    discussion: "",
    version: "1.0.0"
  )

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

  /// Initialize an instance of `NetbotCLITool`.
  public init() {}

  public func run() async throws {
    var profile = try await loadProfile()

    // Overrides settings with input options
    profile.basicSettings.socksListenAddress =
      socksListenAddress ?? profile.basicSettings.socksListenAddress
    profile.basicSettings.socksListenPort = socksListenPort ?? profile.basicSettings.socksListenPort
    profile.basicSettings.httpListenAddress =
      httpListenAddress ?? profile.basicSettings.httpListenAddress
    profile.basicSettings.httpListenPort = httpListenPort ?? profile.basicSettings.httpListenPort
    profile.basicSettings.logLevel = logLevel ?? profile.basicSettings.logLevel

    // Bootstrap Logger with specified logLevel that defined in profile and overrided by input option
    LoggingSystem.bootstrap { label in
      var handler = StreamLogHandler.standardOutput(label: label)
      handler.logLevel = profile.basicSettings.logLevel
      return handler
    }
    let logger = Logger(label: "io.tenbits.Netbot")

    // Default GeoLite2 database file url.
    #if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    let maxminddbURL: URL
    if #available(iOS 16.0, macOS 13.0, tvOS 16.0, watchOS 9.0, *) {
      maxminddbURL = URL.supportDirectory.appending(path: "GeoLite2-Country.mmdb")
    } else {
      maxminddbURL = URL.supportDirectory.appendingPathComponent("GeoLite2-Country.mmdb")
    }
    #else
    let maxminddbURL = URL.supportDirectory.appendingPathComponent("GeoLite2-Country.mmdb")
    #endif
    // Also for GeoLite2 database
    try FileManager.default.createDirectory(
      at: URL.supportDirectory,
      withIntermediateDirectories: true
    )

    // Perform GeoLite2-Country.mmdb downloading...
    if !FileManager.default.fileExists(atPath: maxminddbURL.path) {
      logger.trace("Downloading GeoLite2-Country.mmdb")
      logger.trace("Downloading from https://git.io/GeoLite2-Country.mmdb")
      let (url, _) = try await URLSession(configuration: .ephemeral).download(
        from: URL(string: "https://git.io/GeoLite2-Country.mmdb")!
      )

      try FileManager.default.moveItem(at: url, to: maxminddbURL)
    }

    try await App.init(
      profile: profile,
      outboundMode: outboundMode,
      enableHTTPCapture: enableHTTPCapture,
      enableMitm: enableMitm
    )
    .run()
  }

  private func loadProfile() async throws -> Profile {
    var profile: Profile = .init()
    if let profileFile {
      #if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
      let profileURL: URL
      if #available(iOS 16.0, macOS 13.0, tvOS 16.0, watchOS 9.0, *) {
        profileURL = URL(filePath: profileFile, directoryHint: .notDirectory)
      } else {
        profileURL = URL(fileURLWithPath: profileFile)
      }
      #else
      let profileURL = URL(fileURLWithPath: profileFile)
      #endif

      profile = try Profile(contentsOf: profileURL)
    }

    // External resources will be downloaded and saved into `URL.externalResourcesDirectory`,
    // so we need to make sure an directory is here
    try FileManager.default.createDirectory(
      at: URL.externalResourcesDirectory,
      withIntermediateDirectories: true
    )

    for (position, rule) in profile.rules.enumerated() {
      guard var resources = rule as? ExternalRuleResources & ParsableRule else {
        continue
      }

      #if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
      let fileURL: URL
      if #available(iOS 16.0, macOS 13.0, tvOS 16.0, watchOS 9.0, *) {
        fileURL = URL.externalResourcesDirectory.appending(
          path: resources.externalResourcesStorageName,
          directoryHint: .notDirectory
        )
      } else {
        fileURL = URL.externalResourcesDirectory.appendingPathComponent(
          resources.externalResourcesStorageName,
          isDirectory: false
        )
      }
      #else
      let fileURL = URL.externalResourcesDirectory.appendingPathComponent(
        resources.externalResourcesStorageName,
        isDirectory: false
      )
      #endif

      // Downloading external resources...
      let (srcURL, _) = try await URLSession(configuration: .ephemeral).download(
        from: resources.externalResourcesURL
      )

      // Remove older file first if exists.
      if FileManager.default.fileExists(atPath: fileURL.path) {
        try FileManager.default.removeItem(at: fileURL)
      }
      try FileManager.default.moveItem(at: srcURL, to: fileURL)

      resources.loadAllRules(from: fileURL)

      profile.rules[position] = resources
    }

    return profile
  }
}
