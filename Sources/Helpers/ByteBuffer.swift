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

import NIOCore

extension ByteBuffer {
    
    public mutating func parseUnwindingIfNeeded<T>(_ closure: (inout ByteBuffer) throws -> T?) rethrows -> T? {
        let save = self
        do {
            guard let value = try closure(&self) else {
                self = save
                return nil
            }
            return value
        } catch {
            self = save
            throw error
        }
    }
}
