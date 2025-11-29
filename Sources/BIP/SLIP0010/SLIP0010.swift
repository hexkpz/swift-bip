//
//  Created by Anton Spivak
//

import Foundation

// MARK: - SLIP0010

/// https://slips.readthedocs.io/en/latest/slip-0010/
public enum SLIP0010 {
    public enum Error: Swift.Error {
        // The function CKDpub((Kpar, cpar), i) → (Ki, ci) computes a child extended public key from the parent extended public key.
        // It is only defined for non-hardened child keys.
        case invalidKeyIndex
    }
}

// MARK: - SLIP0010.Error + LocalizedError

extension SLIP0010.Error: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidKeyIndex: "Hardened child keys indicies are only supported"
        }
    }
}
