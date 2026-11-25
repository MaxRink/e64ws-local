import Foundation

/// A type-erased `Encodable`, so a request body can be built with ordinary
/// literals (`["limit": .int(20)]`) and encoded by `JSONEncoder`.
public struct AnyEncodable: Encodable, Sendable {
    public enum Value: Sendable {
        case int(Int)
        case string(String)
        case bool(Bool)
        case double(Double)
    }

    public let value: Value

    public init(_ value: Value) {
        self.value = value
    }

    public static func int(_ value: Int) -> AnyEncodable { AnyEncodable(.int(value)) }
    public static func string(_ value: String) -> AnyEncodable { AnyEncodable(.string(value)) }
    public static func bool(_ value: Bool) -> AnyEncodable { AnyEncodable(.bool(value)) }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch value {
        case .int(let int): try container.encode(int)
        case .string(let string): try container.encode(string)
        case .bool(let bool): try container.encode(bool)
        case .double(let double): try container.encode(double)
        }
    }
}

extension Dictionary where Key == String, Value == AnyEncodable {
    /// Encode this request body to JSON.
    public func encoded() throws -> Data {
        try JSONEncoder().encode(self)
    }
}
