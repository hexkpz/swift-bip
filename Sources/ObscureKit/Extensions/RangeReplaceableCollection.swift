//
//  Created by Anton Spivak
//

import Foundation
import Crypto

#if canImport(Security)
import Security
#endif

public extension RangeReplaceableCollection where Element == UInt8 {
    static func randomBytes(with length: Int) -> Self {
        #if canImport(Security)
        var bytes = [UInt8](repeating: 0, count: length)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess
        else { fatalError("Couldn't generate random bytes") }
        return Self(bytes)
        #else
        /// https://github.com/swiftlang/swift/blob/3707e49f9578fb828cb6a81442f20ba853a3fd31/stdlib/public/core/Random.swift#L134C27-L135C13
        /// https://developer.apple.com/documentation/swift/systemrandomnumbergenerator
        ///
        /// While the system generator is automatically seeded and thread-safe on every platform,
        /// the cryptographic quality of the stream of random data produced by the generator may vary.
        /// For more detail, see the documentation for the APIs used by each platform.
        ///
        /// Apple platforms use arc4random_buf(3).
        /// Linux platforms use getrandom(2) when available; otherwise, they read from /dev/urandom.
        /// Windows uses BCryptGenRandom.
        var generator = SystemRandomNumberGenerator()
        return Self((0 ..< length).map({ _ in .random(in: 0 ... .max, using: &generator) }))
        #endif
    }
}

public extension RangeReplaceableCollection where Element == UInt8 {
    var sha256: Data { SHA256.hash(data: Data(self)).withUnsafeBytes({ Data($0) }) }
    var sha512: Data { SHA512.hash(data: Data(self)).withUnsafeBytes({ Data($0) }) }

    func hmac<H>(_ function: H.Type, with key: any ContiguousBytes) -> Data where H: HashFunction {
        var hmac = HMAC<H>(key: SymmetricKey(data: key))
        hmac.update(data: Data(self))
        return Data(hmac.finalize())
    }
}
