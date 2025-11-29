//
//  Created by Anton Spivak
//

import Foundation
import Testing

@testable import BIP

// MARK: - BIP32Tests

final class BIP32Tests {
    typealias Vector = (
        mnemonica: BIP39.Mnemonica,
        derivationPath: DerivationPath,
        privateKey: String,
        publicKey: String
    )

    @Test("", arguments: [
        (
            "solve volcano that zebra miss dune vacuum emotion phone offer smoke stumble",
            "m/44'/0'/0'/0",
            "4a90b06688cfb2bf4a5690e2ff65dec30be33f5bf57729444c268aa0fd402163",
            "030b50f2f7ecc1a763d57e6e70e71d0f1bd16ea54e165a2a3d6efdbccc695f3a38",
        ),
        (
            "solve volcano that zebra miss dune vacuum emotion phone offer smoke stumble",
            "m/44'/2'/100000/1'",
            "f3a5da2e9e13ff85c2b0115087dce936a0bf6d360ff24ac1fa8ff6c8b732c69d",
            "037e040ac1b21f2bd71423b000ebb62314646d9e1e410b228d9b79c529f702cb9e",
        ),
        (
            "solve volcano that zebra miss dune vacuum emotion phone offer smoke stumble",
            "m/17'",
            "ee8c73974b92687886e036806df27d4db77f46588b9de4b82aba24eedf0e23f5",
            "0294c0630acd945cdbe5edbfdc5be01e4dc717a6a349ea48c4f026f64e07a15b3b",
        ),
    ])
    func secp256k1_0(_ vector: Vector) throws {
        let privateKey = try secp256k1.PrivateKey(
            vector.mnemonica,
            algorithm: .ethereum(),
            derivationPath: vector.derivationPath
        )

        #expect(privateKey.rawRepresentation.hexadecimalString == vector.privateKey)
        #expect(privateKey.publicKey.rawRepresentation.hexadecimalString == vector.publicKey)
    }
}
