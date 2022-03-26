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

struct DocumentParser {
    
    private var byteBuffer: ByteBuffer
    
    private var previous: UInt8?
    
    init(byteBuffer: ByteBuffer) {
        self.byteBuffer = byteBuffer
    }
    
    enum LineValue {
        case comment(String)
        case blank
        case section(String)
        case string(String)
        case object((String, String))
    }
    
    mutating func parse() throws -> [LineValue] {
        var lines: [LineValue] = []
        
        while let next = try parseLine() {
            lines.append(next)
        }
        
        return lines
    }
    
    private mutating func parseLine() throws -> LineValue? {
        consumeWhitespace()
        
        guard let ascii = peek() else {
            return nil
        }
        
        switch (ascii, previous) {
            case (.octothorpe, _), (.semicolon, _):
                self.previous = ascii
                return .comment(readStringTillNextLine())
            case (.openbracket, _):
                self.previous = ascii
                return .section(readStringTillNextLine())
            case (.newLine, .some(.newLine)):
                self.pop()
                self.previous = ascii
                return .blank
            case (.newLine, _):
                // empty line, skip
                self.pop()
                // then parse next
                self.previous = ascii
                return try parseLine()
            default:
                self.previous = ascii
                // this is a valid line, parse it
                return parseLine0()
        }
    }
    
    private mutating func parseLine0() -> LineValue {
        let keyLength = self.byteBuffer.countDistance(to: .equal)
        let maxLength = self.byteBuffer.countDistance(to: .newLine) ?? self.byteBuffer.readableBytes
        
        // Ensure that have equal mark and the equal is in current line.
        guard let keyLength = keyLength, keyLength <= maxLength else {
            return .string(readStringTillNextLine())
        }
        
        let key = self.byteBuffer.readString(length: keyLength)!.trimmingCharacters(in: .whitespaces)
        
        self.pop() // =
        
        return .object((key, readStringTillNextLine()))
    }
    
    private mutating func consumeWhitespace() {
        while let ascii = self.peek() {
            guard case .space = ascii else {
                break
            }
            self.pop()
        }
    }
    
    private mutating func peek() -> UInt8? {
        self.byteBuffer.getInteger(at: self.byteBuffer.readerIndex)
    }
    
    private mutating func pop() {
        self.byteBuffer.moveReaderIndex(forwardBy: 1)
    }
    
    private mutating func readStringTillNextLine() -> String {
        let readLength = self.byteBuffer.countDistance(to: .newLine) ?? self.byteBuffer.readableBytes
        
        let output = self.byteBuffer.readString(length: readLength)!
        
        guard let first = output.first, let last = output.last else {
            return output.trimmingCharacters(in: .whitespaces)
        }
        // check for quoted strings
        switch (first, last) {
            case ("\"", "\""):
                // double quoted strings support escaped \n
                return output.dropFirst().dropLast()
                    .replacingOccurrences(of: "\\n", with: "\n")
                    .trimmingCharacters(in: .whitespaces)
            case ("'", "'"):
                // single quoted strings just need quotes removed
                return (output.dropFirst().dropLast() + "").trimmingCharacters(in: .whitespaces)
            default: return output.trimmingCharacters(in: .whitespaces)
        }
    }
}

extension ByteBuffer {
    
    fileprivate func countDistance(to byte: UInt8) -> Int? {
        var copy = self
        var found = false
        while let next = copy.readInteger(as: UInt8.self) {
            if next == byte {
                found = true
                break
            }
        }
        guard found else {
            return nil
        }
        let distance = copy.readerIndex - self.readerIndex
        guard distance != 0 else {
            return nil
        }
        return distance - 1
    }
}

extension UInt8 {
    
    internal static let space = UInt8(ascii: " ")
    internal static let `return` = UInt8(ascii: "\r")
    internal static let newLine = UInt8(ascii: "\n")
    internal static let tab = UInt8(ascii: "\t")
    
    internal static let octothorpe = UInt8(ascii: "#")
    internal static let semicolon = UInt8(ascii: ";")
    internal static let colon = UInt8(ascii: ":")
    internal static let comma = UInt8(ascii: ",")
    
    internal static let openbrace = UInt8(ascii: "{")
    internal static let closebrace = UInt8(ascii: "}")
    
    internal static let openbracket = UInt8(ascii: "[")
    internal static let closebracket = UInt8(ascii: "]")
    
    internal static let quote = UInt8(ascii: "\"")
    internal static let backslash = UInt8(ascii: "\\")
    
    internal static let equal = UInt8(ascii: "=")
}
