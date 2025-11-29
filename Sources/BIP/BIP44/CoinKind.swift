//
//  Created by Anton Spivak
//

// MARK: - BIP44.CoinKind

public extension BIP44 {
    struct CoinKind: RawRepresentable, Sendable, Hashable {
        // MARK: Lifecycle

        public init(rawValue: BIP32.DerivationPath.KeyIndex) {
            self.rawValue = rawValue
        }

        // MARK: Public

        public var rawValue: BIP32.DerivationPath.KeyIndex
    }
}

public extension BIP44.CoinKind {
    init(_ rawValue: BIP32.DerivationPath.KeyIndex) {
        self.init(rawValue: rawValue)
    }
}

/// - note: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
public extension BIP44.CoinKind {
    static let testnet = BIP44.CoinKind(BIP32.DerivationPath.KeyIndex(rawValue: 0x8000_0001))

    static let bitcoin = BIP44.CoinKind(BIP32.DerivationPath.KeyIndex(rawValue: 0x8000_0000))
    static let litecoin = BIP44.CoinKind(BIP32.DerivationPath.KeyIndex(rawValue: 0x8000_0002))
    static let dogecoin = BIP44.CoinKind(BIP32.DerivationPath.KeyIndex(rawValue: 0x8000_0003))
    static let ethereum = BIP44.CoinKind(BIP32.DerivationPath.KeyIndex(rawValue: 0x8000_003C))
    static let tron = BIP44.CoinKind(BIP32.DerivationPath.KeyIndex(rawValue: 0x8000_00C3))
    static let ton = BIP44.CoinKind(BIP32.DerivationPath.KeyIndex(rawValue: 0x8000_025F))
    static let bsc = BIP44.CoinKind(BIP32.DerivationPath.KeyIndex(rawValue: 0x8000_0207))
    static let matic = BIP44.CoinKind(BIP32.DerivationPath.KeyIndex(rawValue: 0x8000_03C6))
}
