//
//  Created by Anton Spivak
//

// MARK: - BIP32.DerivationPath.KeyIndex

public extension BIP32.DerivationPath {
    enum KeyIndex {
        case ordinary(Int32)
        case hardened(Int32)
    }
}

// MARK: - BIP32.DerivationPath.KeyIndex + RawRepresentable

extension BIP32.DerivationPath.KeyIndex: RawRepresentable {
    public init(rawValue: UInt32) {
        self = switch rawValue {
        case 0 ..< .highestBit: .ordinary(Int32(rawValue))
        default: .hardened(Int32(rawValue - .highestBit))
        }
    }

    public var rawValue: UInt32 {
        switch self {
        case let .ordinary(value): UInt32(value)
        case let .hardened(value): UInt32(value) | .highestBit
        }
    }
}

// MARK: - BIP32.DerivationPath.KeyIndex + LosslessStringConvertible

extension BIP32.DerivationPath.KeyIndex: LosslessStringConvertible {
    public init?(_ description: String) {
        let hardened = description.unescaped.hasSuffix("`")

        var value = description
        if hardened { value = String(value.dropLast()) }

        guard let _value = Int32(value)
        else { return nil }

        self =
            if hardened { .hardened(_value) }
            else { .ordinary(_value) }
    }

    public var description: String {
        switch self {
        case let .ordinary(value): "\(value)"
        case let .hardened(value): "\(value)`"
        }
    }
}

// MARK: - BIP32.DerivationPath.KeyIndex + ExpressibleByStringLiteral

extension BIP32.DerivationPath.KeyIndex: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) {
        guard let value = BIP32.DerivationPath.KeyIndex(value)
        else { fatalError("Invalid `stringLiteral`: \(value)") }
        self = value
    }
}

// MARK: - BIP32.DerivationPath.KeyIndex + Hashable

extension BIP32.DerivationPath.KeyIndex: Hashable {}

// MARK: - BIP32.DerivationPath.KeyIndex + Sendable

extension BIP32.DerivationPath.KeyIndex: Sendable {}

private extension UInt32 {
    static var highestBit: UInt32 {
        0x8000_0000
    }
}
