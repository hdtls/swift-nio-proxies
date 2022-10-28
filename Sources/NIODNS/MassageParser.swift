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

import NIOCore

class MessageParser {

    private var buffer: ByteBuffer

    init(buffer: ByteBuffer) {
        self.buffer = buffer
    }

    func parse() throws -> Message {
        guard buffer.readableBytes >= 12 else {
            throw ResolverError.invalidPayloadData
        }

        guard
            let id = buffer.readInteger(as: UInt16.self),
            let flags = buffer.readInteger(as: UInt16.self),
            let questionCount = buffer.readInteger(as: UInt16.self),
            let answerCount = buffer.readInteger(as: UInt16.self),
            let authorityCount = buffer.readInteger(as: UInt16.self),
            let additionalRecordCount = buffer.readInteger(as: UInt16.self)
        else {
            throw ResolverError.invalidPayloadData
        }

        let options = Message.Options(rawValue: flags)

        var questions: [Question] = []
        for _ in 0..<questionCount {
            questions.append(try parseQuestion())
        }

        var answers: [ResourceRecord] = []
        for _ in 0..<answerCount {
            answers.append(try parseResourceRecord())
        }

        var authorities: [ResourceRecord] = []
        for _ in 0..<authorityCount {
            authorities.append(try parseResourceRecord())
        }

        var additionRecords: [ResourceRecord] = []
        for _ in 0..<additionalRecordCount {
            additionRecords.append(try parseResourceRecord())
        }

        return Message(
            id: id,
            options: options,
            questions: questions,
            answers: answers,
            authorities: authorities,
            additionalRecords: additionRecords
        )
    }

    private func parseLabels() throws -> [String] {
        var labels: [String] = []

        while let length = buffer.readInteger(as: UInt8.self) {
            guard length != 0 else {
                break
            }

            guard let label = buffer.readString(length: Int(length)) else {
                throw ResolverError.invalidPayloadData
            }
            labels.append(label)
        }

        return labels
    }

    private func parseQuestion() throws -> Question {
        let labels = try parseLabels()

        guard let questionType = buffer.readInteger(as: UInt16.self) else {
            throw ResolverError.invalidPayloadData
        }

        guard let rawValue = buffer.readInteger(as: UInt16.self),
            let questionClass = Question.Class(rawValue: rawValue)
        else {
            throw ResolverError.invalidPayloadData
        }

        return Question(labels: labels, questionType: questionType, questionClass: questionClass)
    }

    private func parseResourceRecord() throws -> ResourceRecord {
        let labels = try parseLabels()

        guard
            let recordType = buffer.readInteger(as: UInt16.self),
            let recordClass = buffer.readInteger(as: UInt16.self),
            let ttl = buffer.readInteger(as: UInt32.self),
            let l = buffer.readInteger(as: UInt16.self),
            buffer.readableBytes >= Int(l)
        else {
            throw ResolverError.invalidPayloadData
        }

        guard let data = buffer.readBytes(length: Int(l)) else {
            throw ResolverError.invalidPayloadData
        }

        return ResourceRecord(
            labels: labels,
            recordType: recordType,
            recordClass: recordClass,
            ttl: ttl,
            resource: data
        )
    }
}
