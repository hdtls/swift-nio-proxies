//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// THIS FILE IS MOSTLY COPIED FROM [swift-crypto](https://github.com/apple/swift-crypto)

import Foundation

enum ByteHexEncodingErrors: Error {
  case incorrectHexValue
  case incorrectString
}

let charA = UInt8(UnicodeScalar("a").value)
let char0 = UInt8(UnicodeScalar("0").value)

private func itoh(_ value: UInt8) -> UInt8 {
  return (value > 9) ? (charA + value - 10) : (char0 + value)
}

private func htoi(_ value: UInt8) throws -> UInt8 {
  switch value {
  case char0...char0 + 9:
    return value - char0
  case charA...charA + 5:
    return value - charA + 10
  default:
    throw ByteHexEncodingErrors.incorrectHexValue
  }
}

extension DataProtocol {

  public func hexEncodedString() -> String {
    let hexLen = self.count * 2
    var hexChars = [UInt8](repeating: 0, count: hexLen)
    var offset = 0

    for _ in self.regions {
      for i in self {
        hexChars[Int(offset * 2)] = itoh((i >> 4) & 0xF)
        hexChars[Int(offset * 2 + 1)] = itoh(i & 0xF)
        offset += 1
      }
    }

    return String(bytes: hexChars, encoding: .utf8)!
  }
}

extension Data {

  public init?<S>(hexEncoded hexString: S) where S: StringProtocol {
    if hexString.count % 2 != 0 || hexString.count == 0 {
      return nil
    }

    self.init()

    let stringBytes: [UInt8] = Array(hexString.lowercased().data(using: .utf8)!)

    for i in stride(from: stringBytes.startIndex, to: stringBytes.endIndex - 1, by: 2) {
      let char1 = stringBytes[i]
      let char2 = stringBytes[i + 1]

      guard let newElement = try? htoi(char1) << 4 + htoi(char2) else {
        return nil
      }
      self.append(newElement)
    }
  }
}

extension Array where Element == UInt8 {

  public init?<S>(hexEncoded hexString: S) where S: StringProtocol {
    guard hexString.count.isMultiple(of: 2), !hexString.isEmpty else {
      return nil
    }

    self.init()

    let stringBytes: [UInt8] = Array(hexString.data(using: String.Encoding.utf8)!)

    for i in stride(from: stringBytes.startIndex, to: stringBytes.endIndex - 1, by: 2) {
      let char1 = stringBytes[i]
      let char2 = stringBytes[i + 1]

      guard let newElement = try? htoi(char1) << 4 + htoi(char2) else {
        return nil
      }
      self.append(newElement)
    }
  }
}
