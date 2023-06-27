//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2023 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NEAppEssentials
import XCTest

@testable import NECLICore

final class ProxyTests: XCTestCase {

  let base64EncodedP12String =
    "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"

  func testDecodeProxy() throws {
    let proxyString =
      "{\"algorithm\":\"AES-256-GCM\",\"authenticationRequired\":true,\"certificatePinning\":\"MIIKPwIBAzCCCgYGCSqGSIb3DQEHAaCCCfcEggnzMIIJ7zCCBGcGCSqGSIb3DQEHBqCCBFgwggRUAgEAMIIETQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIMS\\/Omaol11sCAggAgIIEICIvmL+gZSFA+2e1GDIu19M1uYopcuPCGPCaZbXoQ87P6xf\\/\\/qIiuZ9tBaVbdLm7CFUeTnBH725SXSdYdwXeLAcjydfiWqcDoSTVpDiXe+S37R2UnEeg5yZFzM2hjRpLet+P5S+wiIRC2XjZgCK0Em7id0D50AeepTFGeN0TukY\\/HqZj+aG\\/OnCNNo8AnQ\\/P1yCc+ytTTcqKVJt3u1bABpRPQaf\\/fYEOBAZSGr\\/vGz21COGrHAlYinT+rYi43nuIVTQZdmSKeXFfaLPJsIl9rn8Yz9eQ9jT5ErjPUPfucjEHrG9Da5X9aD1j8RYXd9Y440EIwp4PoATz71CCkZEQ++FL992JF95Qy9sSpGFkeU3VIbv0vXQvcqQf0jAwVSERWbjB5A+LiHDUqYC0d\\/cxWr37a0iKXcPgTvrwiSSlgW7iiwLsdQgEwinBItTR1K+jPpNWkHyoJ81oU2GCM0qcGoDXpIgqKJhhG4TxiIp1qy8J5W6HPwRIPkAVLVBeQBg2Mhj\\/keaNqXCTC2I50OuAuPncM15N61+TMXFhVBxsarJrG3Dcb0laf\\/MafVarne8\\/8ADrf2F6I\\/R0uavQqjgxmTcIbrLyXP7iZAaksOHSsECG4jw7dOcA3osO6sH+yRul5bqJdUrqDf1u2vtjtCvCJGhfwzwlH79ifKtofkaq59rR0d0LzwJ4QfhgttE2ax43J4sQ8VIHEmMJW1HrzvOsPRBUNFVuZJPKunFKePtoGpH3SMW8qSPNzaHE+\\/yhNZQV0aO55XugfuPoJstEsrRsUj1u31gCXNHgO5cVs4nwzP0iilmssWQIVT0KTi9IDHcK+8tttOAF3B56hs\\/EDHNLecF6m1ENnbhtIlt\\/mULZ6jrJcRrWsW1VULXXcRmZ+kIEm9y0d5vtHf+M2AO+pcwAkhMGVUPOrfv0Oq1n4+JiHeoP7m1oj71FklaHksBoOpoLsZ0wTW2lAmXh4II\\/If6kj5XaZNdggYbvwLcEQBIvzk012q\\/rLnCoLojzjHMPd7fSRgZ3LjblkS\\/Z8vyAqrJE3Tl9oV+mqbGgkxH9WG0IsbCahHP3XSVUdNm5RD3vdDtXEgtjPZtTef+qKDeCHTHpzF9W4nlZjCWZ6hLgC8UnWgqMTVSJI4QOgIoRNpXf6XFc9JUSEFEouyq5v4LykWKS43NKV4pTS\\/NY6LR9GdoaOWC8Ykpj6ZPtAbTUvb0iRSa6hwf4Yhc5msAks8LWgnVUQMbO3wxkuDa6MJf\\/HuoHxhd0y5FBL47nd49tWFg4+DXzH64\\/gWXWMPhhOB1zmmXcg3q9kO15dR7h4XCxOnoYgCEaPNFrYc3ed1dKqU6RH20lhbwUCykTJDkFdc21q0LYuGfpU4ov3AJvR1yeKgh2WyBJ7prNVnF2k4IUBB+bA5XCYDCCBYAGCSqGSIb3DQEHAaCCBXEEggVtMIIFaTCCBWUGCyqGSIb3DQEMCgECoIIE7jCCBOowHAYKKoZIhvcNAQwBAzAOBAj+Bzy35X5qfgICCAAEggTI9GLmCbW9dpbESlxX7VHBcWXV5PpVFif79q8UTpbMO3SVEJ6DD8jdgfYCRRCQTe7Ovs4m4ySdlJC3XmYnv+h4dihjuY2ZTJ+nt89GQTurEXomVgeR22I1KiCO29\\/ZYxJGsAqnDKnl0RM0F+2Te9kiSSEfgaFWLYR+8h8mgy6q8wyDTecWRqyJQ4Rm+aHTyKVF8pMQh3R6lQJpG\\/s14t1qhUv2rK+WAJfruSvbv2ZXtRZJ4xuI7LIYzT00vrd2s9whH0znTcGTrL9seiOaZVG0bIR8o\\/Roat6Yigh+oQxdERYNdRbTD2g4akLolve\\/8mgwUpG3XHRKdIQkcclUoCJKB4Bjjxo9kRtdTvUx+fCASmLtXSNin7NMEMeydrSfe\\/tYUYtBHarzdKC5Cu6xzRbOe6zByKSv7xk6xOtYG0kc6Gy+DlvQNW1C+s+qEHZ\\/V26VwVskQpUnSkw3jR4JEIJICcanw0pqqtdqKuzwhuvWihwGCiRkVIqqJmODEHAZThTaeDo07kc0JPq7hsK9zenVvirAlyaBdF8EmRfAgx4Q8\\/jRdyIHONKNohvYNsbzscTHlOpqZNTdIPbmlxSiCoLpkWd4Fdc9oQ4ta1x41PMd877m0O+KquwxGqwj4emJQLZmMyDn1obr9pAXDFyXJFDusoRPqVB+4x2Ie34Des1FnI00FjVI2HAwM29doaqYuR6yqtkCuxDZ2rLDnrdsTzK\\/7HtuhmjCc6+ZTbbIRK1Y34ojSRwJgFIskGevAjvwRZtbq4GOd3aJXrFAvYNE\\/2RlGBl3oqvap89SLzZsY1k7xSPiJal0DV5im82tAyc23HcRjsG6B9uEDkQb\\/i7+9wqXxhLlJfs\\/et7SXhKmjPNEoUu3tdAwiPvhYg2kIaeyeBdPFpBS6km1th61cjCYX2gpnTtLOb9oBqf\\/GyRQVLhpH9x8pIvjPO2LHTio0XbKT3NYDXzr9SnGm+IX4PwQvWaOwBNYWXj0h4NMHimUA0urtvsrC9DWBIjeybKJAvC6CUs1oWbGfazbBSSKejpeg+Q6mKhac+0PTg2\\/0JQC9LfAgXc72ed4O7kKbhccWBTwrmqC+VuEkGv5\\/gn+J8D2j0pgwqcDzLy+q17QoymSNr136KJvfx025nx\\/C5CEw4xiD6\\/FBnqCyNCt98RYXp9YNLVPxqcEQ0haSbjhjBv+j9quRbNKqA4Tw7vsEKRV\\/6rfsEp0cxiXCQjZ+sYamx3j8Wnm4aUry3URb3itEaKdsnrZcHI6G4UNDx+AjG68f4cCNkHmjBVbGsREunZnEiEzsXWpsz5piCxT5t0b9XYDOZGotnRwpFIki2DorW4+8w+ItYVLYQaoDPl1K7UoJM5zmtGfH7\\/tfCn1gwJYAnyj2yU544KyhI6HflAKHdADuIVZdHcRSTQ2Cl3qMdIogrQe5d2WG6wRU2Wo\\/jA2j4zANC2s9qKqYxajCwfHfACzisjihxjGwzcgJ1jBm0tC2dQA2IhQg+IqXlbPx2BMc4\\/6jfetmVeKhXpaA0jB9s67kP1JM7mdkLb9A0di8uMcNos1Uv0bGyNYQncbQ8HeV7aGxxg9fBNWPgPCP8kIJKFiEmrZxBfG4YYtf+iN+JrP5Z\\/NvukBooC2+p1+Jq\\/bMWQwIwYJKoZIhvcNAQkVMRYEFMbkckLpQhQd891xl1MJiI4JN\\/DuMD0GCSqGSIb3DQEJFDEwHi4ATgBlAHQAYgBvAHQAIABSAG8AbwB0ACAAQwBBACAAQwBTADIAVQBOAEIARABSMDAwITAJBgUrDgMCGgUABBTv0DZW5WGOyttIiEY23f3RInSpEwQIoXlbDNrNFtcCAQE=\",\"overTls\":true,\"password\":\"123456\",\"port\":8080,\"prefererHttpTunneling\":true,\"protocol\":\"http\",\"serverAddress\":\"127.0.0.1\",\"skipCertificateVerification\":true,\"sni\":\"example.com\",\"username\":\"test\"}"
    let proxy = try JSONDecoder().decode(Proxy.self, from: proxyString.data(using: .utf8)!)

    XCTAssertEqual(proxy.serverAddress, "127.0.0.1")
    XCTAssertEqual(proxy.port, 8080)
    XCTAssertEqual(proxy.protocol, .http)
    XCTAssertEqual(proxy.username, "test")
    XCTAssertEqual(proxy.password, "123456")
    XCTAssertEqual(proxy.passwordReference, "123456")
    XCTAssertEqual(proxy.authenticationRequired, true)
    XCTAssertEqual(proxy.prefererHttpTunneling, true)
    XCTAssertEqual(proxy.overTls, true)
    XCTAssertEqual(proxy.skipCertificateVerification, true)
    XCTAssertEqual(proxy.sni, "example.com")
    XCTAssertEqual(proxy.certificatePinning, base64EncodedP12String)
    XCTAssertEqual(proxy.algorithm, .aes256Gcm)
  }

  func testDefaultValueWorksWhenDecodingProxy() throws {
    let proxyString = "{\"port\":8080,\"protocol\":\"http\",\"serverAddress\":\"127.0.0.1\"}"

    let proxy = try JSONDecoder().decode(Proxy.self, from: proxyString.data(using: .utf8)!)

    XCTAssertEqual(proxy.serverAddress, "127.0.0.1")
    XCTAssertEqual(proxy.port, 8080)
    XCTAssertEqual(proxy.protocol, .http)
    XCTAssertEqual(proxy.username, "")
    XCTAssertEqual(proxy.password, "")
    XCTAssertEqual(proxy.passwordReference, "")
    XCTAssertEqual(proxy.authenticationRequired, false)
    XCTAssertEqual(proxy.prefererHttpTunneling, false)
    XCTAssertEqual(proxy.overTls, false)
    XCTAssertEqual(proxy.skipCertificateVerification, false)
    XCTAssertEqual(proxy.sni, "")
    XCTAssertEqual(proxy.certificatePinning, "")
  }

  func testEncodeProxy() throws {
    let expectedProxyString =
      "{\"algorithm\":\"AES-256-GCM\",\"authenticationRequired\":true,\"certificatePinning\":\"MIIKPwIBAzCCCgYGCSqGSIb3DQEHAaCCCfcEggnzMIIJ7zCCBGcGCSqGSIb3DQEHBqCCBFgwggRUAgEAMIIETQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIMS\\/Omaol11sCAggAgIIEICIvmL+gZSFA+2e1GDIu19M1uYopcuPCGPCaZbXoQ87P6xf\\/\\/qIiuZ9tBaVbdLm7CFUeTnBH725SXSdYdwXeLAcjydfiWqcDoSTVpDiXe+S37R2UnEeg5yZFzM2hjRpLet+P5S+wiIRC2XjZgCK0Em7id0D50AeepTFGeN0TukY\\/HqZj+aG\\/OnCNNo8AnQ\\/P1yCc+ytTTcqKVJt3u1bABpRPQaf\\/fYEOBAZSGr\\/vGz21COGrHAlYinT+rYi43nuIVTQZdmSKeXFfaLPJsIl9rn8Yz9eQ9jT5ErjPUPfucjEHrG9Da5X9aD1j8RYXd9Y440EIwp4PoATz71CCkZEQ++FL992JF95Qy9sSpGFkeU3VIbv0vXQvcqQf0jAwVSERWbjB5A+LiHDUqYC0d\\/cxWr37a0iKXcPgTvrwiSSlgW7iiwLsdQgEwinBItTR1K+jPpNWkHyoJ81oU2GCM0qcGoDXpIgqKJhhG4TxiIp1qy8J5W6HPwRIPkAVLVBeQBg2Mhj\\/keaNqXCTC2I50OuAuPncM15N61+TMXFhVBxsarJrG3Dcb0laf\\/MafVarne8\\/8ADrf2F6I\\/R0uavQqjgxmTcIbrLyXP7iZAaksOHSsECG4jw7dOcA3osO6sH+yRul5bqJdUrqDf1u2vtjtCvCJGhfwzwlH79ifKtofkaq59rR0d0LzwJ4QfhgttE2ax43J4sQ8VIHEmMJW1HrzvOsPRBUNFVuZJPKunFKePtoGpH3SMW8qSPNzaHE+\\/yhNZQV0aO55XugfuPoJstEsrRsUj1u31gCXNHgO5cVs4nwzP0iilmssWQIVT0KTi9IDHcK+8tttOAF3B56hs\\/EDHNLecF6m1ENnbhtIlt\\/mULZ6jrJcRrWsW1VULXXcRmZ+kIEm9y0d5vtHf+M2AO+pcwAkhMGVUPOrfv0Oq1n4+JiHeoP7m1oj71FklaHksBoOpoLsZ0wTW2lAmXh4II\\/If6kj5XaZNdggYbvwLcEQBIvzk012q\\/rLnCoLojzjHMPd7fSRgZ3LjblkS\\/Z8vyAqrJE3Tl9oV+mqbGgkxH9WG0IsbCahHP3XSVUdNm5RD3vdDtXEgtjPZtTef+qKDeCHTHpzF9W4nlZjCWZ6hLgC8UnWgqMTVSJI4QOgIoRNpXf6XFc9JUSEFEouyq5v4LykWKS43NKV4pTS\\/NY6LR9GdoaOWC8Ykpj6ZPtAbTUvb0iRSa6hwf4Yhc5msAks8LWgnVUQMbO3wxkuDa6MJf\\/HuoHxhd0y5FBL47nd49tWFg4+DXzH64\\/gWXWMPhhOB1zmmXcg3q9kO15dR7h4XCxOnoYgCEaPNFrYc3ed1dKqU6RH20lhbwUCykTJDkFdc21q0LYuGfpU4ov3AJvR1yeKgh2WyBJ7prNVnF2k4IUBB+bA5XCYDCCBYAGCSqGSIb3DQEHAaCCBXEEggVtMIIFaTCCBWUGCyqGSIb3DQEMCgECoIIE7jCCBOowHAYKKoZIhvcNAQwBAzAOBAj+Bzy35X5qfgICCAAEggTI9GLmCbW9dpbESlxX7VHBcWXV5PpVFif79q8UTpbMO3SVEJ6DD8jdgfYCRRCQTe7Ovs4m4ySdlJC3XmYnv+h4dihjuY2ZTJ+nt89GQTurEXomVgeR22I1KiCO29\\/ZYxJGsAqnDKnl0RM0F+2Te9kiSSEfgaFWLYR+8h8mgy6q8wyDTecWRqyJQ4Rm+aHTyKVF8pMQh3R6lQJpG\\/s14t1qhUv2rK+WAJfruSvbv2ZXtRZJ4xuI7LIYzT00vrd2s9whH0znTcGTrL9seiOaZVG0bIR8o\\/Roat6Yigh+oQxdERYNdRbTD2g4akLolve\\/8mgwUpG3XHRKdIQkcclUoCJKB4Bjjxo9kRtdTvUx+fCASmLtXSNin7NMEMeydrSfe\\/tYUYtBHarzdKC5Cu6xzRbOe6zByKSv7xk6xOtYG0kc6Gy+DlvQNW1C+s+qEHZ\\/V26VwVskQpUnSkw3jR4JEIJICcanw0pqqtdqKuzwhuvWihwGCiRkVIqqJmODEHAZThTaeDo07kc0JPq7hsK9zenVvirAlyaBdF8EmRfAgx4Q8\\/jRdyIHONKNohvYNsbzscTHlOpqZNTdIPbmlxSiCoLpkWd4Fdc9oQ4ta1x41PMd877m0O+KquwxGqwj4emJQLZmMyDn1obr9pAXDFyXJFDusoRPqVB+4x2Ie34Des1FnI00FjVI2HAwM29doaqYuR6yqtkCuxDZ2rLDnrdsTzK\\/7HtuhmjCc6+ZTbbIRK1Y34ojSRwJgFIskGevAjvwRZtbq4GOd3aJXrFAvYNE\\/2RlGBl3oqvap89SLzZsY1k7xSPiJal0DV5im82tAyc23HcRjsG6B9uEDkQb\\/i7+9wqXxhLlJfs\\/et7SXhKmjPNEoUu3tdAwiPvhYg2kIaeyeBdPFpBS6km1th61cjCYX2gpnTtLOb9oBqf\\/GyRQVLhpH9x8pIvjPO2LHTio0XbKT3NYDXzr9SnGm+IX4PwQvWaOwBNYWXj0h4NMHimUA0urtvsrC9DWBIjeybKJAvC6CUs1oWbGfazbBSSKejpeg+Q6mKhac+0PTg2\\/0JQC9LfAgXc72ed4O7kKbhccWBTwrmqC+VuEkGv5\\/gn+J8D2j0pgwqcDzLy+q17QoymSNr136KJvfx025nx\\/C5CEw4xiD6\\/FBnqCyNCt98RYXp9YNLVPxqcEQ0haSbjhjBv+j9quRbNKqA4Tw7vsEKRV\\/6rfsEp0cxiXCQjZ+sYamx3j8Wnm4aUry3URb3itEaKdsnrZcHI6G4UNDx+AjG68f4cCNkHmjBVbGsREunZnEiEzsXWpsz5piCxT5t0b9XYDOZGotnRwpFIki2DorW4+8w+ItYVLYQaoDPl1K7UoJM5zmtGfH7\\/tfCn1gwJYAnyj2yU544KyhI6HflAKHdADuIVZdHcRSTQ2Cl3qMdIogrQe5d2WG6wRU2Wo\\/jA2j4zANC2s9qKqYxajCwfHfACzisjihxjGwzcgJ1jBm0tC2dQA2IhQg+IqXlbPx2BMc4\\/6jfetmVeKhXpaA0jB9s67kP1JM7mdkLb9A0di8uMcNos1Uv0bGyNYQncbQ8HeV7aGxxg9fBNWPgPCP8kIJKFiEmrZxBfG4YYtf+iN+JrP5Z\\/NvukBooC2+p1+Jq\\/bMWQwIwYJKoZIhvcNAQkVMRYEFMbkckLpQhQd891xl1MJiI4JN\\/DuMD0GCSqGSIb3DQEJFDEwHi4ATgBlAHQAYgBvAHQAIABSAG8AbwB0ACAAQwBBACAAQwBTADIAVQBOAEIARABSMDAwITAJBgUrDgMCGgUABBTv0DZW5WGOyttIiEY23f3RInSpEwQIoXlbDNrNFtcCAQE=\",\"overTls\":true,\"password\":\"123456\",\"port\":8080,\"prefererHttpTunneling\":true,\"protocol\":\"http\",\"serverAddress\":\"127.0.0.1\",\"skipCertificateVerification\":true,\"sni\":\"example.com\",\"username\":\"test\"}"

    let proxy = Proxy(
      serverAddress: "127.0.0.1",
      port: 8080,
      protocol: .http,
      username: "test",
      password: "123456",
      authenticationRequired: true,
      prefererHttpTunneling: true,
      overTls: true,
      skipCertificateVerification: true,
      sni: "example.com",
      certificatePinning: base64EncodedP12String,
      algorithm: .aes256Gcm
    )

    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys
    let proxyString = String(data: try encoder.encode(proxy), encoding: .utf8)

    XCTAssertEqual(proxyString, expectedProxyString)
  }

  func testEncodeDefaultProxy() throws {
    let expectedProxyString =
      "{\"port\":8080,\"protocol\":\"http\",\"serverAddress\":\"127.0.0.1\"}"

    let proxy = Proxy(serverAddress: "127.0.0.1", port: 8080, protocol: .http)

    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys
    let proxyString = String(data: try encoder.encode(proxy), encoding: .utf8)

    XCTAssertEqual(proxyString, expectedProxyString)
  }
}
