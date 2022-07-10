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

/// All communications inside of the domain protocol are carried in a single
/// format called a message.  The top level format of message is divided
/// into 5 sections (some of which are empty in certain cases) shown below:
///
///     +---------------------+
///     |        Header       |
///     +---------------------+
///     |       Question      | the question for the name server
///     +---------------------+
///     |        Answer       | RRs answering the question
///     +---------------------+
///     |      Authority      | RRs pointing toward an authority
///     +---------------------+
///     |      Additional     | RRs holding additional information
///     +---------------------+
///
/// The header section is always present.  The header includes fields that
/// specify which of the remaining sections are present, and also specify
/// whether the message is a query or a response, a standard query or some
/// other opcode, etc.
///
/// The names of the sections after the header are derived from their use in
/// standard queries.  The question section contains fields that describe a
/// question to a name server.  These fields are a query type (QTYPE), a
/// query class (QCLASS), and a query domain name (QNAME).  The last three
/// sections have the same format: a possibly empty list of concatenated
/// resource records (RRs).  The answer section contains RRs that answer the
/// question; the authority section contains RRs that point toward an
/// authoritative name server; the additional records section contains RRs
/// which relate to the query, but are not strictly answers for the
/// question.
struct Message {

    struct Options: OptionSet, ExpressibleByIntegerLiteral {
        var rawValue: UInt16

        init(rawValue: UInt16) {
            self.rawValue = rawValue
        }

        init(integerLiteral value: UInt16) {
            self.rawValue = value
        }

        static let answer: Options = 0b10000000_00000000

        /// Authoritative Answer - this bit is valid in responses,
        /// and specifies that the responding name server is an
        /// authority for the domain name in question section.
        ///
        /// Note that the contents of the answer section may have
        /// multiple owner names because of aliases.  The AA bit
        /// corresponds to the name which matches the query name, or
        /// the first owner name in the answer section.
        static let authorativeAnswer: Options = 0b00000100_00000000

        /// TrunCation - specifies that this message was truncated
        /// due to length greater than that permitted on the
        /// transmission channel.
        static let truncated: Options = 0b00000010_00000000

        /// Recursion Desired - this bit may be set in a query and
        /// is copied into the response.  If RD is set, it directs
        /// the name server to pursue the query recursively.
        /// Recursive query support is optional.
        static let recursionDesired: Options = 0b00000001_00000000

        /// Recursion Available - this be is set or cleared in a
        /// response, and denotes whether recursive query support is
        /// available in the name server.
        static let recursionAvailable: Options = 0b00000000_10000000

        static let standardQuery: Options = 0b00000000_00000000
        static let inverseQuery: Options = 0b00001000_00000000
        static let serverStatusQuery: Options = 0b00010000_00000000

        /// Response code
        static let success: Options = 0b00000000_00000000
        static let formatError: Options = 0b00000000_00000001
        static let serverfailure: Options = 0b00000000_00000010
        static let nameError: Options = 0b00000000_00000011
        static let notImplemented: Options = 0b00000000_00000100
        static let notRefused: Options = 0b00000000_00000101

        var isAnswer: Bool {
            return self.contains(.answer)
        }

        var isAuthorativeAnswer: Bool {
            return self.contains(.authorativeAnswer)
        }

        var isQuestion: Bool {
            return !isAnswer
        }

        var isStandardQuery: Bool {
            return rawValue & 0b01111000_00000000 == Options.standardQuery.rawValue
        }

        var isInverseQuery: Bool {
            return rawValue & 0b01111000_00000000 == Options.inverseQuery.rawValue
        }

        var isServerStatusQuery: Bool {
            return rawValue & 0b01111000_00000000 == Options.serverStatusQuery.rawValue
        }

        var isSuccessful: Bool {
            return self.contains(.success)
        }

        var isFormatError: Bool {
            return self.contains(.formatError)
        }

        var isServerFailure: Bool {
            return self.contains(.serverfailure)
        }

        var isNameError: Bool {
            return self.contains(.nameError)
        }

        var isNotImplemented: Bool {
            return self.contains(.notImplemented)
        }

        var isNotRefused: Bool {
            return self.contains(.notRefused)
        }

        var isRefused: Bool {
            return !isNotRefused
        }
    }

    struct ID {
        static var startPoint: Int = -1

        static var lock = NSLock()

        static func next() -> UInt16 {
            lock.lock()
            defer { lock.unlock() }

            startPoint += 1
            if startPoint > Int(UInt16.max) {
                startPoint = 0
            }

            return min(UInt16(startPoint), .max)
        }
    }

    /// A 16 bit identifier assigned by the program that
    /// generates any kind of query.  This identifier is copied
    /// the corresponding reply and can be used by the requester
    /// to match up replies to outstanding queries.
    var id: UInt16

    var options: Options

    /// Question section.
    var questions: [Question]

    /// Answer section.
    var answers: [ResourceRecord]

    /// Authority section.
    var authorities: [ResourceRecord]

    /// Additional records section.
    var additionalRecords: [ResourceRecord]

    init(
        id: UInt16,
        options: Options,
        questions: [Question],
        answers: [ResourceRecord],
        authorities: [ResourceRecord],
        additionalRecords: [ResourceRecord]
    ) {
        self.id = id
        self.options = options
        self.questions = questions
        self.answers = answers
        self.authorities = authorities
        self.additionalRecords = additionalRecords
    }
}

struct Question {

    enum Class: UInt16 {
        case internet = 1
        case chaos = 3
        case hesoid = 4
    }

    var labels: [String]
    var questionType: UInt16
    var questionClass: Class

    init(labels: [String], questionType: UInt16, questionClass: Class) {
        self.labels = labels
        self.questionType = questionType
        self.questionClass = questionClass
    }
}

struct ResourceRecord {

    let labels: [String]
    let recordType: UInt16
    let recordClass: UInt16
    let ttl: UInt32
    var resource: [UInt8]

    init(
        labels: [String],
        recordType: UInt16,
        recordClass: UInt16,
        ttl: UInt32,
        resource: [UInt8]
    ) {
        self.labels = labels
        self.recordType = recordType
        self.recordClass = recordClass
        self.ttl = ttl
        self.resource = resource
    }
}
