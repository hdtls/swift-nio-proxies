import Foundation

extension Array where Element == UInt8 {
    
    /// Increment array like `sodium_increment(_:)`
    /// - Returns: result value
    mutating func increment(_ length: Int) {
        var c: UInt8 = 1
        self = map { e in
            c += e
            defer { c >>= 8 }
            return c & 0xFF
        }
    }
}
