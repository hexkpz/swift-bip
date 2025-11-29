//
//  Created by Anton Spivak
//

import Foundation

// MARK: - BIP39

/// - note: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
public enum BIP39 {
    public enum Error: Swift.Error {
        case unsupportedMnemonicaLength
        case invalidMnemonicaVocabulary
    }
}

// MARK: - BIP39.Error + LocalizedError

extension BIP39.Error: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .unsupportedMnemonicaLength: "Unsupported mnemonica length"
        case .invalidMnemonicaVocabulary: "Invalid mnemonica words"
        }
    }
}
