//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// A enum representing a SOCKS protocol version.
public enum SOCKSProtocolVersion: UInt8, Equatable {

    /// SOCKS/5
    case v5 = 5
}
