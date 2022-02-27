//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation

public class Session {
    
    let sharedSecretBytes: [UInt8]
    
    var isAEAD: Bool
    
    init(isAEAD: Bool) {
        sharedSecretBytes = Array<UInt8>(capacity: 33)
        self.isAEAD = isAEAD
    }
}
