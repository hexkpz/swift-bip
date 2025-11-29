//
//  Created by Anton Spivak
//

import Foundation
import Crypto

// MARK: - PKCS5

public enum PKCS5 {
    /// https://github.com/orlandos-nl/PBKDF2/blob/main/Sources/PBKDF2/PBKDF2.swift
    public struct PBKDF2<H> where H: HashFunction {
        // MARK: Lifecycle

        public init() {
            self.chunkSize = H.blockByteCount
            self.digestSize = H.Digest.byteCount
        }

        // MARK: Private

        private let chunkSize: Int
        private let digestSize: Int
    }
}

public extension PKCS5.PBKDF2 {
    func calculate(
        password: Data,
        salt: Data,
        iterations: Int,
        derivedKeyLength: Int
    ) -> Data {
        var password = [UInt8](password)

        precondition(!password.isEmpty, "Password could not be empty")
        precondition(!salt.isEmpty, "Salt could not be empty")
        precondition(iterations > 0, "You must iterate in PBKDF2 at least once")
        precondition(derivedKeyLength <= Int(Int32.max) * chunkSize, "Key length too long")

        let saltSize = salt.count
        var salt = salt + [0, 0, 0, 0]

        if password.count > chunkSize {
            password = [UInt8](H.hash(data: password))
        }

        if password.count < chunkSize {
            password = password + [UInt8](repeating: 0, count: chunkSize - password.count)
        }

        var outerPadding = [UInt8](repeating: 0x5C, count: chunkSize)
        var innerPadding = [UInt8](repeating: 0x36, count: chunkSize)

        xor(&innerPadding, password, count: chunkSize)
        xor(&outerPadding, password, count: chunkSize)

        func authenticate(message: UnsafeRawBufferPointer) -> H.Digest {
            var hasher = H()
            hasher.update(data: innerPadding)
            hasher.update(bufferPointer: message)

            let innerPaddingHash = hasher.finalize()

            hasher = H()
            hasher.update(data: outerPadding)

            innerPaddingHash.withUnsafeBytes({ hasher.update(bufferPointer: $0) })
            return hasher.finalize()
        }

        var output = [UInt8]()
        output.reserveCapacity(derivedKeyLength)

        func calculate(block: UInt32) {
            var block = block.bigEndian
            withUnsafeBytes(of: &block, { counterBytes in
                var i = 0
                while i < 4 {
                    salt[saltSize + i] = counterBytes[i]
                    i &+= 1
                }
            })

            var ui: H.Digest = salt.withUnsafeBytes { authenticate(message: $0) }
            var u1 = Array(ui)

            if iterations > 1 {
                for _ in 1 ..< iterations {
                    ui = ui.withUnsafeBytes({ authenticate(message: $0) })
                    xor(&u1, ui, count: digestSize)
                }
            }

            output.append(contentsOf: u1)
        }

        for block in 1 ... UInt32((derivedKeyLength + digestSize - 1) / digestSize) {
            calculate(block: block)
        }

        let extra = output.count &- derivedKeyLength
        if extra >= 0 { output.removeLast(extra) }

        return Data(output)
    }

    private func xor<D: Digest>(_ lhs: inout [UInt8], _ rhs: D, count: Int) {
        rhs.withUnsafeBytes({ rhs in
            precondition(lhs.count == rhs.count)
            var i = 0; while i < count {
                lhs[i] ^= rhs[i]
                i &+= 1
            }
        })
    }

    private func xor(_ lhs: inout [UInt8], _ rhs: [UInt8], count: Int) {
        precondition(lhs.count == rhs.count)
        var i = 0; while i < count {
            lhs[i] ^= rhs[i]
            i &+= 1
        }
    }
}
