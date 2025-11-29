//
//  Created by Anton Spivak
//

@_exported import ObscureKit
@_exported import Crypto

public typealias Mnemonica = BIP39.Mnemonica
public typealias DerivationPath = BIP32.DerivationPath
public typealias HDWallet = BIP44.HDWallet

public extension BIP39.SeedDerivationAlgorithm {
    static func ethereum(
        password: String = "",
        iterations: Int = 2048,
        klength: Int = 64
    ) -> BIP39.SeedDerivationAlgorithm {
        BIP39.SeedDerivationAlgorithm([.pkcs5(
            salt: "mnemonic",
            password: password,
            iterations: iterations,
            klength: klength
        )])
    }

    static func ton(
        iterations: Int = 100_000,
        klength: Int = 32
    ) -> BIP39.SeedDerivationAlgorithm {
        BIP39.SeedDerivationAlgorithm([
            .hmac(kind: .sha512),
            .pkcs5(
                salt: "TON default seed",
                password: "",
                iterations: iterations,
                klength: klength
            ),
        ])
    }
}
