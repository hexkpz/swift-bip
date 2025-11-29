//
//  Created by Anton Spivak
//

import Foundation
import Crypto

public extension Curve25519.Signing.PrivateKey {
    init(
        _ mnemonica: BIP39.Mnemonica,
        algorithm: BIP39.SeedDerivationAlgorithm,
        hdWallet: BIP44.HDWallet
    ) throws(SLIP0010.Error) {
        try self.init(mnemonica.seed(with: algorithm), derivationPath: hdWallet.derivationPath)
    }

    init(
        _ mnemonica: BIP39.Mnemonica,
        algorithm: BIP39.SeedDerivationAlgorithm,
        derivationPath: BIP32.DerivationPath
    ) throws(SLIP0010.Error) {
        try self.init(mnemonica.seed(with: algorithm), derivationPath: derivationPath)
    }

    init<D>(
        _ seed: D,
        hdWallet: BIP44.HDWallet
    ) throws(SLIP0010.Error) where D: DataProtocol {
        try self.init(seed, derivationPath: hdWallet.derivationPath)
    }

    init<D>(
        _ seed: D,
        derivationPath: BIP32.DerivationPath
    ) throws(SLIP0010.Error) where D: DataProtocol {
        var tuple = Self.masterKeyPair(seed)
        for index in derivationPath.indices {
            tuple = try Self.next(tuple.privateKey, with: index, chain: tuple.chain)
        }
        self = tuple.privateKey
    }
}

private extension Curve25519.Signing.PrivateKey {
    static func masterKeyPair<D>(
        _ seed: D
    ) -> (privateKey: Curve25519.Signing.PrivateKey, chain: Data) where D: DataProtocol {
        let tuple = _master(from: Data(seed))
        let privateKey = try! Curve25519.Signing.PrivateKey(rawRepresentation: tuple.key)
        return (privateKey, tuple.chain)
    }

    static func next(
        _ privateKey: Curve25519.Signing.PrivateKey,
        with index: BIP32.DerivationPath.KeyIndex,
        chain: Data
    ) throws(SLIP0010.Error) -> (privateKey: Curve25519.Signing.PrivateKey, chain: Data) {
        var bytes = Data()

        switch index {
        case .ordinary:
            throw .invalidKeyIndex
        case .hardened:
            bytes.append(contentsOf: [0x00])
            bytes.append(contentsOf: privateKey.rawRepresentation)
        }

        var rawIndex: UInt32 = index.rawValue.bigEndian
        bytes.append(contentsOf: withUnsafeBytes(of: &rawIndex, { Data($0) }))

        let derived = _key(from: bytes, key: chain)
        return try! (Curve25519.Signing.PrivateKey(rawRepresentation: derived.key), derived.chain)
    }

    private static func _master(from seed: Data) -> (key: Data, chain: Data) {
        _key(from: seed, key: Data("ed25519 seed".utf8))
    }

    private static func _key(from value: Data, key: Data) -> (key: Data, chain: Data) {
        let hash = value.hmac(SHA512.self, with: key)
        return (hash[..<32], hash[32...])
    }
}
