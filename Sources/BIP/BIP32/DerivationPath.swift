//
//  Created by Anton Spivak
//

// MARK: - BIP32.DerivationPath

public extension BIP32 {
    struct DerivationPath: Sendable, Hashable {
        // MARK: Lifecycle

        public init(_ kind: KeyKind = .master, _ indices: [KeyIndex]) {
            self.kind = kind
            self.indices = indices
        }

        // MARK: Public

        public let kind: KeyKind
        public let indices: [KeyIndex]
    }
}

// MARK: - BIP32.DerivationPath + RawRepresentable

extension BIP32.DerivationPath: RawRepresentable {
    public init?(rawValue: String) {
        let elements = rawValue.unescaped.components(separatedBy: "/")
        guard elements.count >= 1, let keyKind = KeyKind(elements[0])
        else { return nil }

        let indices: [KeyIndex] =
            if elements.count > 1 { elements[1 ..< elements.count].compactMap({ KeyIndex($0) }) }
            else { [] }

        guard indices.count == elements.count - 1
        else { return nil }

        self = BIP32.DerivationPath(keyKind, indices)
    }

    public var rawValue: String {
        ([kind.description] + indices.map({ $0.description })).joined(separator: "/")
    }
}

// MARK: - BIP32.DerivationPath + LosslessStringConvertible

extension BIP32.DerivationPath: LosslessStringConvertible {
    public init?(_ description: String) {
        self.init(rawValue: description)
    }

    public var description: String {
        rawValue
    }
}

// MARK: - BIP32.DerivationPath + ExpressibleByStringLiteral

extension BIP32.DerivationPath: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) {
        guard let derivationPath = BIP32.DerivationPath(value)
        else { fatalError("Invalid `stringLiteral`: \(value)") }
        self = derivationPath
    }
}

// MARK: - BIP32.DerivationPath + Codable

extension BIP32.DerivationPath: Codable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let rawValue = try container.decode(String.self)

        guard let derivationPath = BIP32.DerivationPath(rawValue: rawValue) else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Couldn't decode `BIP32.DerivationPath` from \(container)"
            )
        }

        self = derivationPath
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}
