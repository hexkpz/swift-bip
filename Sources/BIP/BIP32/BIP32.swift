//
//  Created by Anton Spivak
//

import Foundation

// MARK: - BIP32

/// - note: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
public enum BIP32 {
    public enum Error: Swift.Error {
        /// Invalid child key: IL is zero or produces a private key outside the secp256k1 range
        case invalidChildKey
    }
}

// MARK: - BIP32.Error + LocalizedError

extension BIP32.Error: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidChildKey: "Unsupported mnemonica length"
        }
    }
}
