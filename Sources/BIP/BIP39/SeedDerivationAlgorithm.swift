//
//  Created by Anton Spivak
//

import Foundation
import ObscureKit

// MARK: - BIP39.SeedDerivationAlgorithm

public extension BIP39 {
    struct SeedDerivationAlgorithm: Sendable, Hashable {
        // MARK: Lifecycle

        public init(_ steps: [Step]) {
            self.steps = steps
        }

        // MARK: Public

        public enum Step: Sendable, Hashable {
            case hmac(kind: HashingFunction)
            case pkcs5(salt: String, password: String, iterations: Int, klength: Int)
        }

        public enum HashingFunction: Sendable, Hashable {
            case sha512

            // MARK: Internal

            var _function: (some HashFunction).Type {
                switch self {
                case .sha512: SHA512.self
                }
            }
        }

        public var steps: [Step]
    }
}

extension BIP39.SeedDerivationAlgorithm {
    func derive(_ mnemonica: Mnemonica) -> Data {
        var value = Data(mnemonica.rawValue.joined(separator: " ")._normalized.utf8)
        for step in steps {
            switch step {
            case let .hmac(kind):
                value = Data().hmac(kind._function, with: value)
            case let .pkcs5(salt, password, iterations, klength):
                value = PKCS5.PBKDF2<SHA512>().calculate(
                    password: value,
                    salt: Data("\(salt)\(password)"._normalized.utf8),
                    iterations: iterations,
                    derivedKeyLength: klength
                )
            }
        }
        return value
    }
}

private extension String {
    var _normalized: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}
