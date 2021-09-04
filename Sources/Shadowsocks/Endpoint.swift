import Foundation
import NIOCore

/// The address used to connect to the target host.
public enum Endpoint: CustomStringConvertible {
    case domainPort(String, Int)
    case socketAddress(SocketAddress)
    
    public var description: String {
        switch self {
            case .domainPort(let domain, let port):
                return "\(domain):\(port)..."
            case .socketAddress(let addr):
                return addr.description
        }
    }
}

extension Data {
    
    /// Applies the given task address to this collection.
    /// - Parameter address: task address
    mutating func applying(_ address: Endpoint) {
        
        switch address {
            case .socketAddress(let a):
                switch a {
                    case .v4(let addr):
                        append(0x01)
                        Swift.withUnsafeBytes(of: addr.address.sin_addr) {
                            append(contentsOf: $0)
                        }
                        Swift.withUnsafeBytes(of: addr.address.sin_port.bigEndian) {
                            append(contentsOf: $0)
                        }
                    case .v6(let addr):
                        append(0x04)
                        Swift.withUnsafeBytes(of: addr.address.sin6_addr) {
                            append(contentsOf: $0)
                        }
                        
                        Swift.withUnsafeBytes(of: addr.address.sin6_port.bigEndian) {
                            append(contentsOf: $0)
                        }
                    case .unixDomainSocket(_):
                        preconditionFailure("UNIX domain sockets are not supported.")
                }
            case .domainPort(let domain, let port):
                append(0x03)
                append(UInt8(domain.count))
                append(domain.data(using: .utf8)!)
                Swift.withUnsafeBytes(of: UInt16(port).bigEndian) {
                    append(contentsOf: $0)
                }
        }
    }
    
    func asEndpoint() throws -> Endpoint? {
        var byteBuffer = ByteBuffer(bytes: self)
        let type = byteBuffer.readInteger(as: UInt8.self)
        
        switch type {
            case 0x01:
                return try byteBuffer.parseUnwindingIfNeeded { buffer in
                    guard let packedIPAddress = buffer.readSlice(length: 4), let port = buffer.readInteger(as: UInt16.self) else {
                        return nil
                    }
                    return .socketAddress(try .init(packedIPAddress: packedIPAddress, port: Int(port)))
                }
            case 0x02:
                return try byteBuffer.parseUnwindingIfNeeded { buffer in
                    guard let packedIPAddress = buffer.readSlice(length: 16), let port = buffer.readInteger(as: UInt16.self) else {
                        return nil
                    }
                    return .socketAddress(try .init(packedIPAddress: packedIPAddress, port: Int(port)))
                }
            case 0x03:
                return byteBuffer.parseUnwindingIfNeeded { buffer in
                    guard let length = buffer.readInteger(as: UInt8.self), let host = buffer.readString(length: Int(length)), let port = buffer.readInteger(as: UInt16.self) else {
                        return nil
                    }
                    return .domainPort(host, Int(port))
                }
            default:
                assertionFailure("illegal address type.")
                return nil
        }
    }
}
