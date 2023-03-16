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

/// A `ParsableRule` is a route that define matching conditions and policies for proxy routing
public protocol ParsableRule: LosslessStringConvertible, Sendable {

    /// The expression fot this rule.
    ///
    /// If rule is collection expression is used to save external resources url string.
    var expression: String { get set }

    /// The policy pointed to by the rule.
    var policy: String { get set }

    /// Initialize an instance of `ParsableRule` with specified expression and policy.
    init(expression: String, policy: String)

    /// Rule evaluating function to determinse whether this rule match the given expression.
    /// - Returns: True if match else false.
    func match(_ expression: String) -> Bool
}

public struct FinalRule: ParsableRule {

    public var expression: String

    public var policy: String

    public var description: String {
        "FINAL,\(policy)"
    }

    public init(expression: String, policy: String) {
        self.expression = ""
        self.policy = policy
    }

    public init(policy: String) {
        self.expression = ""
        self.policy = policy
    }

    public init?(_ description: String) {
        // Rule definitions are comma-separated.
        let components = description.components(separatedBy: ",").map {
            $0.trimmingCharacters(in: .whitespaces)
        }

        guard components.count == 2, components.first == "FINAL" else {
            return nil
        }

        expression = ""
        policy = components.last!
    }

    public func match(_ pattern: String) -> Bool {
        true
    }
}
