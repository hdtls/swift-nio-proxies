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

#if compiler(>=5.1)
@_implementationOnly import CMMDB
#else
import CMMDB
#endif
import Foundation

public struct GeoLiteInternalError: Equatable, CustomStringConvertible {
    
    public let errorCode: Int32
    
    init(errorCode: Int32) {
        self.errorCode = errorCode
    }
    
    public var description: String {
        String(cString: MMDB_strerror(errorCode))
    }
}

public enum GeoLiteError: Error {
    case unknowError(GeoLiteInternalError)
}

public final class GeoLite2 {
    
    var db: MMDB_s = .init()
        
    /// Initialize `GeoLite2` from file path.
    /// - Parameter file: The path for `GeoLite2.mmdb` file.
    public init(file: String) throws {
        let status = file.withCString {
            MMDB_open($0, UInt32(MMDB_MODE_MMAP), &db)
        }
        
        guard status == MMDB_SUCCESS else {
            throw GeoLiteError.unknowError(GeoLiteInternalError(errorCode: status))
        }
    }
    
    /// Query country ISO code for given ip address.
    /// - Parameter ipAddress: Query parameter.
    /// - Returns: ISO code string.
    public func queryCountryISOCodeWithIPAddress(_ ipAddress: String) throws -> String? {
        var gaiError: Int32 = 0
        var error: Int32 = MMDB_SUCCESS
        
        var result = ipAddress.withCString {
            MMDB_lookup_string(&db, $0, &gaiError, &error)
        }
        
        if gaiError != 0 {
            // TODO: Error handling
            return nil
        }
        
        if error != MMDB_SUCCESS {
            throw GeoLiteError.unknowError(GeoLiteInternalError(errorCode: error))
        }
        
        guard result.found_entry else {
            return nil
        }
        
        var data: MMDB_entry_data_s = .init();
    
        error = ["country", "iso_code"].withCStrings {
            withVaList($0) { va_list in
                MMDB_vget_value(&result.entry, &data, va_list)
            }
        }

        guard error == MMDB_SUCCESS else {
            throw GeoLiteError.unknowError(GeoLiteInternalError(errorCode: error))
        }
        
        guard data.has_data else {
            return nil
        }
        
        return String(cString: strndup(data.utf8_string, Int(data.data_size)))
    }
    
    deinit {
        MMDB_close(&db)
    }
}

extension Collection where Element == String {
    /// Converts an array of strings to an array of C strings, without copying.
    fileprivate func withCStrings<R>(_ body: ([UnsafePointer<CChar>]) throws -> R) rethrows -> R {
        return try withCStrings(head: [], body: body)
    }
    
    // Recursively call withCString on each of the strings.
    private func withCStrings<R>(head: [UnsafePointer<CChar>],
                                 body: ([UnsafePointer<CChar>]) throws -> R) rethrows -> R {
        if let next = self.first {
            // Get a C string, add it to the result array, and recurse on the remainder of the collection
            return try next.withCString { cString in
                var head = head
                head.append(cString)
                return try dropFirst().withCStrings(head: head, body: body)
            }
        } else {
            // Base case: no more strings; call the body closure with the array we've built
            return try body(head)
        }
    }
}
