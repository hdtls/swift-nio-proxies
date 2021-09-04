import Foundation
import Crypto

/// Generate key like `Evp_BytesToKey`.
/// - Parameters:
///   - data: user input password
///   - keyByteCount: key length for deliver key.
///   - saltByteCount: salt length for deliver key.
/// - Returns: hash result
@inline(__always)
func deliverKey(_ data: String, saltByteCount: Int, outputByteCount: Int) -> [UInt8] {
    var i = 0
    var initialResult: [UInt8] = []
    var partialResult: [UInt8] = []
    while initialResult.count < outputByteCount + saltByteCount {
        var bytes = Array(data.utf8)
        if i > 0 {
            bytes = partialResult + bytes
        }
        partialResult = Array(Insecure.MD5.hash(data: bytes))
        initialResult.append(contentsOf: partialResult)
        i += 1
    }
    return Array(initialResult.prefix(outputByteCount))
}

func hkdfDerivedSymmetricKey<Salt: DataProtocol>(password: String, salt: Salt, outputByteCount: Int) -> SymmetricKey {
    let inputKeyMaterial = SymmetricKey(data: deliverKey(password, saltByteCount: salt.count, outputByteCount: outputByteCount))
    let info = "ss-subkey".data(using: .utf8)!
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS))
    if #available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *) {
        return HKDF<Insecure.SHA1>.deriveKey(inputKeyMaterial: inputKeyMaterial, salt: salt, info: info, outputByteCount: outputByteCount)
    } else {
        // TODO: Fallback on earlier versions
        assertionFailure("TODO: Fallback on earlier version")
        return .init(size: .bits256)
    }
#else
    return HKDF<Insecure.SHA1>.deriveKey(inputKeyMaterial: inputKeyMaterial, salt: salt, info: info, outputByteCount: outputByteCount)
#endif
}
