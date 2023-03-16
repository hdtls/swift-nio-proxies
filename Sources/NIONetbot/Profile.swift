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

/// A profile object that defines behavior and policies for a Netbot process.
public struct Profile: Sendable {

    /// The rules contains in this configuration.
    public var rules: [any ParsableRule]

    /// A setting object that provides HTTP MitM settings for this process.
    public var manInTheMiddleSettings: ManInTheMiddleSettings

    /// A setting object that provides basic settings for this process.
    public var basicSettings: BasicSettings

    /// All proxy policy object contains in this configuration object.
    public var policies: [any Policy]

    /// All selectable policy groups contains in this configuration object.
    public var policyGroups: [any PolicyGroup]

    /// Initialize an instance of `Profile` with the specified basicSettings, replicat, rules, manInTheMiddleSettings,
    /// polcies and policyGroups.
    public init(
        basicSettings: BasicSettings,
        rules: [any ParsableRule],
        manInTheMiddleSettings: ManInTheMiddleSettings,
        policies: [any Policy],
        policyGroups: [any PolicyGroup]
    ) {
        self.basicSettings = basicSettings
        self.rules = rules
        self.manInTheMiddleSettings = manInTheMiddleSettings
        self.policies = policies
        self.policyGroups = policyGroups
    }

    /// Initialize an `Profile`.
    ///
    /// Calling this method is equivalent to calling
    /// `init(basicSettings:rules:manInTheMiddleSettings:policies:policyGroups:)`
    /// with a default basicSettings, replica rules, manInTheMiddleSettings, policies and policyGroups object.
    public init() {
        self.init(
            basicSettings: .init(),
            rules: .init(),
            manInTheMiddleSettings: .init(),
            policies: .init(),
            policyGroups: .init()
        )
    }
}

/// Selectable policy group object that defines policy group and current selected policy.
public protocol PolicyGroup: Sendable {

    /// The name for this PolicyGroup.
    var name: String { get set }

    /// Policies included in this policy group.
    var policies: [String] { get set }
}
