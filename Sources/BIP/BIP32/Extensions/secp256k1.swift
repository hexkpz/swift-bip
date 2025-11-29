//
//  Created by Anton Spivak
//

import Foundation
import ObscureKit
import BigInt
import Crypto

// MARK: - BIP32.ExtendedKey

public extension secp256k1.PrivateKey {
    init(
        _ mnemonica: BIP39.Mnemonica,
        algorithm: BIP39.SeedDerivationAlgorithm,
        hdWallet: BIP44.HDWallet
    ) throws(BIP32.Error) {
        try self.init(mnemonica.seed(with: algorithm), derivationPath: hdWallet.derivationPath)
    }

    init(
        _ mnemonica: BIP39.Mnemonica,
        algorithm: BIP39.SeedDerivationAlgorithm,
        derivationPath: BIP32.DerivationPath
    ) throws(BIP32.Error) {
        try self.init(mnemonica.seed(with: algorithm), derivationPath: derivationPath)
    }

    init<D>(
        _ seed: D,
        hdWallet: BIP44.HDWallet
    ) throws(BIP32.Error) where D: DataProtocol {
        try self.init(seed, derivationPath: hdWallet.derivationPath)
    }

    init<D>(
        _ seed: D,
        derivationPath: BIP32.DerivationPath
    ) throws(BIP32.Error) where D: DataProtocol {
        var tuple = Self.masterKeyPair(seed)
        for index in derivationPath.indices {
            tuple = try Self.next(tuple.privateKey, with: index, chain: tuple.chain)
        }
        self = tuple.privateKey
    }
}

extension secp256k1.PrivateKey {
    static func masterKeyPair<D>(
        _ seed: D
    ) -> (privateKey: secp256k1.PrivateKey, chain: Data) where D: DataProtocol {
        let tuple = _master(from: Data(seed))
        let privateKey = try! secp256k1.PrivateKey(tuple.key)
        return (privateKey, tuple.chain)
    }

    static func next(
        _ privateKey: secp256k1.PrivateKey,
        with index: BIP32.DerivationPath.KeyIndex,
        chain: Data
    ) throws(BIP32.Error) -> (privateKey: secp256k1.PrivateKey, chain: Data) {
        var bytes = Data()

        switch index {
        case .ordinary:
            bytes.append(contentsOf: privateKey.publicKey.rawRepresentation)
        case .hardened:
            bytes.append(contentsOf: [0x00])
            bytes.append(contentsOf: privateKey.rawRepresentation)
        }

        var rawIndex: UInt32 = index.rawValue.bigEndian
        bytes.append(contentsOf: withUnsafeBytes(of: &rawIndex, { Data($0) }))

        let derived = _key(from: bytes, key: chain)

        let factor = BigUInt(Data(derived.key))
        guard factor > 0 && factor < .curveOrder
        else { throw .invalidChildKey }

        let parent = BigUInt(Data(privateKey.rawRepresentation))
        let child = (parent + factor) % .curveOrder
        guard child > 0
        else { throw .invalidChildKey }

        var privateKey = child.serialize()
        if privateKey.count < 32 {
            privateKey.insert(contentsOf: Data(repeating: 0, count: 32 - privateKey.count), at: 0)
        }

        return try! (secp256k1.PrivateKey(privateKey), derived.chain)
    }

    /// The total number of possible extended keypairs is almost 2^512, but the
    /// produced keys are only 256 bits long, and offer about half of that in
    /// terms of security. Therefore, master keys are not generated directly, but instead from a
    /// potentially short seed value.
    ///
    /// 1. Generate a seed byte sequence S of a chosen length (between 128 and 512 bits; 256 bits is
    /// advised) from a (P)RNG.
    /// 2. Calculate I = HMAC-SHA512(Key = "Bitcoin seed", Data = S)
    /// 3. Split I into two 32-byte sequences, IL and IR.
    /// 4. Use parse256(IL) as master secret key, and IR as master chain code.
    ///
    /// - note: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#master-key-generation
    private static func _master(from seed: Data) -> (key: Data, chain: Data) {
        _key(from: seed, key: Data("Bitcoin seed".utf8))
    }

    private static func _key(from value: Data, key: Data) -> (key: Data, chain: Data) {
        let hash = value.hmac(SHA512.self, with: key)
        return (hash[..<32], hash[32...])
    }
}

private extension BigUInt {
    static let curveOrder: BigUInt = {
        let value = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
        guard let value = BigUInt(value, radix: 16)
        else { fatalError("Couldn't create `curveOrder`.") }
        return value
    }()
}
