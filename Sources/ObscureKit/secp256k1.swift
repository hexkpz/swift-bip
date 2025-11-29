//
//  Created by Anton Spivak
//

import Foundation
import libsecp256k1

// MARK: - secp256k1

public enum secp256k1 {
    // MARK: Public

    public struct Error: LocalizedError {
        // MARK: Lifecycle

        init(_ errorDescription: String?) {
            self.errorDescription = errorDescription
        }

        // MARK: Public

        public let errorDescription: String?
    }

    // MARK: Internal

    nonisolated(unsafe) static var context: OpaquePointer = {
        let flags = UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
        guard let context = secp256k1_context_create(flags)
        else { fatalError("`secp256k1_context_create` failed") }

        var seed: [UInt8] = .randomBytes(with: 32)
        _ = secp256k1_context_randomize(context, &seed)

        return context
    }()

    // MARK: Fileprivate

    fileprivate typealias rsignature = secp256k1_ecdsa_recoverable_signature

    // MARK: Private

    private static func _serialize(publicKey: secp256k1_pubkey, compressed: Bool) -> Data {
        let flags = compressed ?
            UInt32(SECP256K1_EC_COMPRESSED) :
            UInt32(SECP256K1_EC_UNCOMPRESSED)

        var publicKey = publicKey

        var serializedPublicKey = [UInt8](repeating: 0, count: compressed ? 33 : 65)
        var serializedPublicKeyLength = serializedPublicKey.count

        let result = secp256k1_ec_pubkey_serialize(
            secp256k1.context,
            &serializedPublicKey,
            &serializedPublicKeyLength,
            &publicKey,
            flags
        )

        precondition(result == 1, "`secp256k1_ec_pubkey_serialize` failed")
        return Data(serializedPublicKey[0 ..< serializedPublicKeyLength])
    }
}

// MARK: secp256k1.PrivateKey

public extension secp256k1 {
    struct PrivateKey: Sendable, Hashable {
        // MARK: Lifecycle

        public init(_ rawRepresentation: Data) throws(secp256k1.Error) {
            guard rawRepresentation.count == 32
            else { throw secp256k1.Error("secp256k1.PrivateKey must be 32 bytes long") }

            var secretKey = rawRepresentation.withUnsafeBytes({ [UInt8]($0) })
            guard secp256k1_ec_seckey_verify(secp256k1.context, &secretKey) == 1
            else { throw secp256k1.Error("secp256k1.PrivateKey couldn't be validated") }

            self.rawRepresentation = rawRepresentation
        }

        // MARK: Public

        public let rawRepresentation: Data

        public var publicKey: PublicKey {
            publicKey(compressed: true)
        }

        public func publicKey(compressed: Bool) -> PublicKey {
            let publicKey = secp256k1._serialize(publicKey: _publicKey(), compressed: compressed)
            return .init(rawRepresentation: publicKey)
        }

        // MARK: Private

        private func _publicKey() -> secp256k1_pubkey {
            var secretKey = rawRepresentation.withUnsafeBytes({ [UInt8]($0) })

            let publicKey = UnsafeMutablePointer<secp256k1_pubkey>.allocate(capacity: 1)
            defer { publicKey.deallocate() }

            let result = secp256k1_ec_pubkey_create(secp256k1.context, publicKey, &secretKey)
            precondition(result == 1, "`secp256k1_ec_pubkey_create` failed")

            return publicKey.pointee
        }
    }
}

// MARK: secp256k1.Signature

public extension secp256k1 {
    struct Signature: Sendable {
        // MARK: Lifecycle

        public init(r: Data, s: Data, v: UInt8) throws {
            guard r.count == 32, s.count == 32
            else { throw secp256k1.Error("`r|s` must be 64 bytes long") }

            self.r = r
            self.s = s

            self.v = v
        }

        init(_ data: Data, v: UInt8) {
            precondition(data.count == 64)
            self.r = data[0 ..< 32]
            self.s = data[32 ..< 64]
            self.v = v
        }

        // MARK: Public

        public let r: Data
        public let s: Data
        public let v: UInt8

        public var combined: Data { r + s + [v] }
    }
}

public extension secp256k1.PrivateKey {
    func signature<D>(
        for data: D
    ) throws(secp256k1.Error) -> secp256k1.Signature where D: DataProtocol {
        guard data.count == 32
        else { throw secp256k1.Error("`data` must be 32 bytes long") }

        var value = [UInt8](data)
        var secretKey = rawRepresentation.withUnsafeBytes({ [UInt8]($0) })

        let rsignature = UnsafeMutablePointer<secp256k1.rsignature>.allocate(capacity: 1)
        defer { rsignature.deallocate() }

        let result = secp256k1_ecdsa_sign_recoverable(
            secp256k1.context,
            rsignature,
            &value,
            &secretKey,
            nil,
            nil
        )

        precondition(result == 1, "`secp256k1_ecdsa_sign_recoverable` failed")

        let output = UnsafeMutablePointer<UInt8>.allocate(capacity: 64)
        defer { output.deallocate() }

        var recoveryID: Int32 = 0
        secp256k1_ecdsa_recoverable_signature_serialize_compact(
            secp256k1.context,
            output,
            &recoveryID,
            rsignature
        )

        precondition(recoveryID >= 0 && recoveryID < Int32(UInt8.max), "Invalid recoveryID")
        return secp256k1.Signature(Data(bytes: output, count: 64), v: UInt8(recoveryID))
    }
}

// MARK: - secp256k1.PublicKey

public extension secp256k1 {
    struct PublicKey: Sendable, Hashable {
        // MARK: Lifecycle

        public init(rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }

        // MARK: Public

        public let rawRepresentation: Data
    }
}

public extension secp256k1.PublicKey {
    func isValidSignature<D>(
        _ signature: secp256k1.Signature,
        for data: D
    ) throws(secp256k1.Error) -> Bool where D: DataProtocol {
        guard data.count == 32
        else { throw .init("`data` must be 32 bytes long") }

        var value = [UInt8](data)
        var rawRepresentation = [UInt8](rawRepresentation)

        let publicKey = UnsafeMutablePointer<secp256k1_pubkey>.allocate(capacity: 1)
        defer { publicKey.deallocate() }

        let pkresult = secp256k1_ec_pubkey_parse(
            secp256k1.context,
            publicKey,
            &rawRepresentation,
            rawRepresentation.count
        )

        guard pkresult == 1
        else { throw secp256k1.Error("`secp256k1_ec_pubkey_parse` failed") }

        var rawSignature = [UInt8]()
        rawSignature.append(contentsOf: [UInt8](signature.r))
        rawSignature.append(contentsOf: [UInt8](signature.s))
        precondition(rawSignature.count == 64, "r||s must be 64 bytes long")

        let signature = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        defer { signature.deallocate() }

        let sigresult = secp256k1_ecdsa_signature_parse_compact(
            secp256k1.context,
            signature,
            &rawSignature
        )

        guard sigresult == 1 else { return false }
        return secp256k1_ecdsa_verify(secp256k1.context, signature, &value, publicKey) == 1
    }
}

public extension secp256k1.Signature {
    func recoverPublicKey<D>(
        for data: D,
        compressed: Bool = true
    ) throws(secp256k1.Error) -> secp256k1.PublicKey where D: DataProtocol {
        guard data.count == 32
        else { throw .init("`data` must be 32 bytes long") }

        var value = [UInt8](data)

        var rawSignature = [UInt8]()
        rawSignature.append(contentsOf: [UInt8](r))
        rawSignature.append(contentsOf: [UInt8](s))
        precondition(rawSignature.count == 64, "r||s must be 64 bytes long")

        let rsignature = UnsafeMutablePointer<secp256k1.rsignature>.allocate(capacity: 1)
        defer { rsignature.deallocate() }

        let presult = secp256k1_ecdsa_recoverable_signature_parse_compact(
            secp256k1.context,
            rsignature,
            &rawSignature,
            Int32(v)
        )

        guard presult == 1 else {
            throw secp256k1.Error("`secp256k1_ecdsa_recoverable_signature_parse_compact` failed")
        }

        let publicKey = UnsafeMutablePointer<secp256k1_pubkey>.allocate(capacity: 1)
        defer { publicKey.deallocate() }

        let recresult = secp256k1_ecdsa_recover(
            secp256k1.context,
            publicKey,
            rsignature,
            &value
        )

        guard recresult == 1
        else { throw secp256k1.Error("`secp256k1_ecdsa_recover` failed") }

        return .init(rawRepresentation: secp256k1._serialize(
            publicKey: publicKey.pointee,
            compressed: compressed
        ))
    }
}
