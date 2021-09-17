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

import Foundation
import Netbot

let serverIpAddress = "192.168.0.101"

let httpListenAddress = "127.0.0.1"
let httpListenPort = 6152
let socks5ListenAddress = "127.0.0.1"
let socks5ListenPort = 6153

#if canImport(SystemConfiguration)
import SystemConfiguration

let excludeSimpleHostnames = true
let exceptions = "localhost,*.local,localhost,*.apple.com,0.0.0.0/8,10.0.0.0/8,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.168.0.0/16,192.88.99.0/24,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,240.0.0.0/4,255.255.255.255/32"

func enableGlobalProxy() {
    enableProxy(asGlobalProxy: true)
}

func disableGlobalProxy() {
    enableProxy(asGlobalProxy: false)
}

func enableProxy(asGlobalProxy: Bool) {
    var authRef: AuthorizationRef!
    let authFlags: AuthorizationFlags = [.extendRights, .interactionAllowed, .preAuthorize]
    let authError = AuthorizationCreate(nil, nil, authFlags, &authRef)
    
    guard authError == noErr, authRef != nil else {
        fatalError("No authorization has been granted to modify network configuration")
    }
    
    guard let prefs = SCPreferencesCreateWithAuthorization(nil, "Linking" as CFString, nil, authRef) else {
        fatalError("Failed to create system configuration preferences.")
    }
    
    let isEnabled = asGlobalProxy
    
    let exceptionsList = exceptions.split(separator: ",").map(String.init)
    
    var settings: [CFString : Any] = [:]
    settings[kCFNetworkProxiesSOCKSProxy] = isEnabled ? socks5ListenAddress : nil
    settings[kCFNetworkProxiesSOCKSPort] = isEnabled ? socks5ListenPort : nil
    settings[kCFNetworkProxiesSOCKSEnable] = isEnabled ? 1 : 0
    settings[kCFNetworkProxiesHTTPProxy] = isEnabled ? httpListenAddress : nil
    settings[kCFNetworkProxiesHTTPPort] = isEnabled ? httpListenPort : nil
    settings[kCFNetworkProxiesHTTPEnable] = isEnabled ? 1 : 0
    settings[kCFNetworkProxiesHTTPSProxy] = isEnabled ? httpListenAddress : nil
    settings[kCFNetworkProxiesHTTPSPort] = isEnabled ? httpListenPort : nil
    settings[kCFNetworkProxiesHTTPSEnable] = isEnabled ? 1 : 0
    settings[kCFNetworkProxiesExcludeSimpleHostnames] = isEnabled && excludeSimpleHostnames ? 1 : 0
    settings[kCFNetworkProxiesExceptionsList] = isEnabled ? exceptionsList : nil
    
    let networkServices = SCPreferencesGetValue(prefs, kSCPrefNetworkServices)!
    
    var hasChanges = true
    
    networkServices.allKeys?.forEach { key in
        guard let keyValuePairs = networkServices.object(forKey: key) as? NSDictionary else {
            return
        }
        
        guard let hardware = keyValuePairs.value(forKeyPath: "Interface.Hardware") as? String else {
            return
        }
        
        guard ["AirPort", "Wi-Fi", "Ethernet"].contains(hardware) else {
            return
        }
        
        let path = "/\(kSCPrefNetworkServices)/\(key)/\(kSCEntNetProxies)" as CFString
        
        let originalValue = SCPreferencesPathGetValue(prefs, path) as! [CFString : Any]
        
        if originalValue[kCFNetworkProxiesSOCKSProxy] as? String == socks5ListenAddress,
           originalValue[kCFNetworkProxiesSOCKSPort] as? Int == socks5ListenPort,
           originalValue[kCFNetworkProxiesSOCKSEnable] as? Int == (isEnabled ? 1 : 0),
           originalValue[kCFNetworkProxiesHTTPProxy] as? String == httpListenAddress,
           originalValue[kCFNetworkProxiesHTTPPort] as? Int == httpListenPort,
           originalValue[kCFNetworkProxiesHTTPEnable] as? Int == (isEnabled ? 1 : 0),
           originalValue[kCFNetworkProxiesHTTPSProxy] as? String == httpListenAddress,
           originalValue[kCFNetworkProxiesHTTPSPort] as? Int == httpListenPort,
           originalValue[kCFNetworkProxiesHTTPSEnable] as? Int == (isEnabled ? 1 : 0),
           originalValue[kCFNetworkProxiesExcludeSimpleHostnames] as? Int == (isEnabled ? 1 : 0),
           originalValue[kCFNetworkProxiesExceptionsList] as? Array<String> == exceptionsList {
            hasChanges = false
        } else {
            hasChanges = true
            SCPreferencesPathSetValue(prefs, path, settings as CFDictionary)
        }
    }
    
    if hasChanges {
        SCPreferencesCommitChanges(prefs)
        SCPreferencesApplyChanges(prefs)
        SCPreferencesSynchronize(prefs)
    }
    
    AuthorizationFree(authRef, authFlags)
}

enableGlobalProxy()

#endif

LoggingSystem.bootstrap { label in
    var handler = StreamLogHandler.standardOutput(label: label)
    handler.logLevel = .debug
    return handler
}

let baseAddress = try SocketAddress(ipAddress: serverIpAddress, port: 8389)
//let baseAddress = try SocketAddress(ipAddress: serverIpAddress, port: 8385)

let credential = SOCKS.Credential(identity: "Netbot", identityTokenString: "com.netbot.credential")

let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)

let bootstrap = ServerBootstrap(group: eventLoopGroup)
    .serverChannelOption(ChannelOptions.backlog, value: Int32(1024))
    .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: SocketOptionValue(1))
    .childChannelInitializer { channel in
        channel.pipeline.addHandlers([
            HTTPResponseEncoder(),
            ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes)),
            HTTP1ServerCONNECTTunnelHandler { taskAddress in
                ClientBootstrap(group: channel.eventLoop.next())
                    .channelInitializer { client in
                        client.pipeline.addSSClientHandlers(taskAddress: taskAddress, secretKey: credential.identityTokenString)
                        //                        client.pipeline.addSOCKSClientHandlers(taskAddress: taskAddress, credential: credential)
                        //                        client.pipeline.addVMESSClientHandlers(taskAddress: taskAddress)
                    }
                    .connect(to: baseAddress)
            }
        ])
    }
    .childChannelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: SocketOptionValue(1))
    .childChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: SocketOptionValue(1))
    .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 1)

defer {
    try! eventLoopGroup.syncShutdownGracefully()
}

let channel = try bootstrap
    .bind(host: httpListenAddress, port: httpListenPort)
    .wait()

guard let localAddress = channel.localAddress else {
    fatalError("Address was unable to bind. Please check that the socket was not closed or that the address family was understood.")
}

print("Server started and listening on \(localAddress)")

try channel.closeFuture.wait()
