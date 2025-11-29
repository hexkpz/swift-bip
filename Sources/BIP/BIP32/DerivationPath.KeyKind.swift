//
//  Created by Anton Spivak
//

// MARK: - BIP32.DerivationPath.KeyKind

public extension BIP32.DerivationPath {
    enum KeyKind: Sendable, Hashable {
        case master
    }
}

// MARK: - BIP32.DerivationPath.KeyKind + RawRepresentable

extension BIP32.DerivationPath.KeyKind: RawRepresentable {
    public init?(rawValue: String) {
        switch rawValue {
        case "m": self = .master
        default: return nil
        }
    }

    public var rawValue: String {
        switch self {
        case .master: "m"
        }
    }
}

// MARK: - BIP32.DerivationPath.KeyKind + LosslessStringConvertible

extension BIP32.DerivationPath.KeyKind: LosslessStringConvertible {
    public init?(_ description: String) {
        guard let keyKind = BIP32.DerivationPath.KeyKind(rawValue: description.unescaped)
        else { return nil }
        self = keyKind
    }

    public var description: String {
        rawValue
    }
}

// MARK: - BIP32.DerivationPath.KeyKind + ExpressibleByStringLiteral

extension BIP32.DerivationPath.KeyKind: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) {
        guard let keyKind = BIP32.DerivationPath.KeyKind(value)
        else { fatalError("Invalid `stringLiteral`: \(value)") }
        self = keyKind
    }
}
