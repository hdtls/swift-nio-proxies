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

#if os(macOS)
import ArgumentParser
import Foundation
import SystemConfiguration

public struct SystemProxyConfigCommand: ParsableCommand {
  public static var configuration: CommandConfiguration = .init(
    commandName: "sysproxycfg",
    abstract: "System Proxies Config Command Line Tool",
    discussion:
      "This command help user update system proxies settings for SOCKS, web and secure web proxy.",
    subcommands: [InstallCommand.self, UninstallCommand.self]
  )

  public init() {}
}

extension SystemProxyConfigCommand {

  public struct InstallCommand: ParsableCommand {

    public static var configuration: CommandConfiguration = .init(
      commandName: "install",
      abstract: "Install settings for system proxies settings.",
      discussion:
        "This command help user to install SOCKS5, web and secure web proxy settings. \n\nNote: Only when both address and port are set can take effect. Missing any of them will cause the proxy setting to failed. \n\nYou can choose set --xx-listen-address and --xx-listen-port or only use --xx-listen to update settings, if both --xx-listen will be override by --xx-listen-address/port."
    )

    @Option(help: "The SOCKS5 proxy server listen address.")
    public var socksListenAddress: String?

    @Option(help: "The SOCKS5 proxy server listen port.")
    public var socksListenPort: Int?

    @Option(help: "The web and secure web proxy server listen address.")
    public var httpListenAddress: String?

    @Option(help: "The web and secure web proxy server listen port.")
    public var httpListenPort: Int?

    @Flag(help: "Exclude simple hostnames.")
    public var excludeSimpleHostnames: Bool = false

    @Option(help: "Bypass proxy settings for these Hosts & Domains, separated by commas.")
    public var exceptions: String?

    public init() {}

    public func run() throws {
      var authRef: AuthorizationRef!
      let authFlags: AuthorizationFlags = [
        .extendRights, .interactionAllowed, .preAuthorize,
      ]
      let authError = AuthorizationCreate(nil, nil, authFlags, &authRef)

      guard authError == noErr, authRef != nil else {
        fatalError("No authorization has been granted to modify network configuration")
      }

      guard
        let prefs = SCPreferencesCreateWithAuthorization(
          nil,
          "Linking" as CFString,
          nil,
          authRef
        )
      else {
        fatalError("Failed to create system configuration preferences.")
      }

      var settings: [CFString: Any] = [:]

      if let socksListenAddress, let socksListenPort {
        settings[kCFNetworkProxiesSOCKSProxy] = socksListenAddress
        settings[kCFNetworkProxiesSOCKSPort] = socksListenPort
        settings[kCFNetworkProxiesSOCKSEnable] = true
      }

      if let httpListenAddress, let httpListenPort {
        settings[kCFNetworkProxiesHTTPProxy] = httpListenAddress
        settings[kCFNetworkProxiesHTTPPort] = httpListenPort
        settings[kCFNetworkProxiesHTTPEnable] = true
        settings[kCFNetworkProxiesHTTPSProxy] = httpListenAddress
        settings[kCFNetworkProxiesHTTPSPort] = httpListenPort
        settings[kCFNetworkProxiesHTTPSEnable] = true
      }

      settings[kCFNetworkProxiesExcludeSimpleHostnames] = excludeSimpleHostnames
      settings[kCFNetworkProxiesExceptionsList] = exceptions?.split(separator: ",").map(
        String.init
      )

      let networkServices = SCPreferencesGetValue(prefs, kSCPrefNetworkServices)!

      networkServices.allKeys?.forEach { key in
        guard let keyValuePairs = networkServices.object(forKey: key) as? NSDictionary
        else {
          return
        }

        guard
          let hardware = keyValuePairs.value(forKeyPath: "Interface.Hardware")
            as? String
        else {
          return
        }

        guard ["AirPort", "Wi-Fi", "Ethernet"].contains(hardware) else {
          return
        }

        let path = "/\(kSCPrefNetworkServices)/\(key)/\(kSCEntNetProxies)" as CFString

        SCPreferencesPathSetValue(prefs, path, settings as CFDictionary)
      }

      SCPreferencesCommitChanges(prefs)
      SCPreferencesApplyChanges(prefs)
      SCPreferencesSynchronize(prefs)

      AuthorizationFree(authRef, authFlags)
    }
  }

  public struct UninstallCommand: ParsableCommand {

    public static var configuration: CommandConfiguration = .init(
      commandName: "uninstall",
      abstract: "Uninstall system proxies settings.",
      discussion: "This will remove all settings for system proxies settings."
    )

    public init() {}

    public func run() throws {
      var authRef: AuthorizationRef!
      let authFlags: AuthorizationFlags = [
        .extendRights, .interactionAllowed, .preAuthorize,
      ]
      let authError = AuthorizationCreate(nil, nil, authFlags, &authRef)

      guard authError == noErr, authRef != nil else {
        fatalError("No authorization has been granted to modify network configuration")
      }

      guard
        let prefs = SCPreferencesCreateWithAuthorization(
          nil,
          "Linking" as CFString,
          nil,
          authRef
        )
      else {
        fatalError("Failed to create system configuration preferences.")
      }

      let settings: [CFString: Any] = [:]

      let networkServices = SCPreferencesGetValue(prefs, kSCPrefNetworkServices)!

      networkServices.allKeys?.forEach { key in
        guard let keyValuePairs = networkServices.object(forKey: key) as? NSDictionary
        else {
          return
        }

        guard
          let hardware = keyValuePairs.value(forKeyPath: "Interface.Hardware")
            as? String
        else {
          return
        }

        guard ["AirPort", "Wi-Fi", "Ethernet"].contains(hardware) else {
          return
        }

        let path = "/\(kSCPrefNetworkServices)/\(key)/\(kSCEntNetProxies)" as CFString

        SCPreferencesPathSetValue(prefs, path, settings as CFDictionary)
      }

      SCPreferencesCommitChanges(prefs)
      SCPreferencesApplyChanges(prefs)
      SCPreferencesSynchronize(prefs)

      AuthorizationFree(authRef, authFlags)
    }
  }
}
#endif
