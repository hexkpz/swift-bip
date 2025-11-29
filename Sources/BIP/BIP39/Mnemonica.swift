//
//  Created by Anton Spivak
//

import Foundation
import Crypto

// MARK: - BIP39.Mnemonica

public extension BIP39 {
    struct Mnemonica: RawRepresentable, Sendable, Hashable {
        // MARK: Lifecycle

        public init(length: Length, glossary: Glossary = .english) {
            try! self.init(
                entropy: .randomBytes(with: length.entropyBytesCount),
                glossary: glossary
            )
        }

        public init(entropy: Data, glossary: Glossary = .english) throws(BIP39.Error) {
            let rawValue = Self._words(from: entropy, glossary: glossary)

            guard let length = BIP39.Mnemonica.Length(rawValue: rawValue.count)
            else { throw BIP39.Error.unsupportedMnemonicaLength }

            self.init(rawValue: rawValue, length: length, glossary: glossary)
        }

        public init?(rawValue: [String]) {
            let rawValue = rawValue.map({ $0.lowercased() })

            guard let tuple = try? BIP39.Mnemonica.check(rawValue)
            else { return nil }

            self.init(rawValue: rawValue, length: tuple.0, glossary: tuple.1)
        }

        private init(rawValue: [String], length: Length, glossary: Glossary) {
            self.rawValue = rawValue

            self.length = length
            self.glossary = glossary
        }

        // MARK: Public

        public let rawValue: [String]

        public let length: Length
        public let glossary: Glossary

        public var entropy: Data {
            let bits = rawValue.map({
                guard let index = glossary.list.firstIndex(of: $0)
                else { fatalError("Unexpected word: \($0)") }

                var bindex = String(index, radix: 2)
                while bindex.count < 11 {
                    bindex = "0" + bindex
                }

                return bindex
            }).joined()

            let divider = Int(Double(bits.count / 33).rounded(.down) * 32)

            let entropyBits = String(bits.prefix(divider))
            let checksumBits = String(bits.suffix(bits.count - divider))

            let entropyBytes = [UInt8](bitsStringRepresentation: entropyBits)

            guard checksumBits == Self._checksum(entropyBytes)
            else { fatalError("Invalid checksum") }

            return .init(entropyBytes)
        }

        public func seed(with algorithm: SeedDerivationAlgorithm) -> Data {
            algorithm.derive(self)
        }
    }
}

// MARK: - BIP39.Mnemonica + ExpressibleByStringLiteral

extension BIP39.Mnemonica: ExpressibleByStringLiteral {
    public init(stringLiteral value: StringLiteralType) {
        guard let value = BIP39.Mnemonica(value)
        else { fatalError("Invalid `stringLiteral`: \(value)") }
        self = value
    }
}

// MARK: - BIP39.Mnemonica + LosslessStringConvertible

extension BIP39.Mnemonica: LosslessStringConvertible {
    public init?(_ description: String) {
        self.init(rawValue: description.components(separatedBy: " "))
    }

    public var description: String {
        rawValue.joined(separator: " ")
    }
}

private extension BIP39.Mnemonica {
    static func _words(
        from entropy: Data,
        glossary: BIP39.Mnemonica.Glossary
    ) -> [String] {
        let entropyBytes = [UInt8](entropy)
        let checksumBits = _checksum(entropyBytes)
        let entropyBits = String(entropyBytes.flatMap({
            ("00000000" + String($0, radix: 2)).suffix(8)
        }))

        let bits = entropyBits + checksumBits

        let vocabulary = glossary.list
        var words = [String]()

        for i in 0 ..< (bits.count / 11) {
            let startIndex = bits.index(bits.startIndex, offsetBy: i * 11)
            let endIndex = bits.index(bits.startIndex, offsetBy: (i + 1) * 11)

            guard let index = Int(bits[startIndex ..< endIndex], radix: 2)
            else { fatalError("Unexpected bit value") }

            words.append(vocabulary[index])
        }

        return words
    }

    private static func _checksum(_ entropyBytes: [UInt8]) -> String {
        let size = (entropyBytes.count * 8) / 32
        let hash = SHA256.hash(data: entropyBytes)
        let hashBits = String(hash.flatMap({
            ("00000000" + String($0, radix: 2)).suffix(8)
        }))
        return String(hashBits.prefix(size))
    }
}

private extension BIP39.Mnemonica {
    @discardableResult
    static func check(_ words: [String]) throws(BIP39.Error) -> (Length, Glossary) {
        guard let length = BIP39.Mnemonica.Length(rawValue: words.count)
        else { throw .unsupportedMnemonicaLength }

        var glossary: Glossary?
        for item in Glossary.allCases {
            guard item.validate(words) else { continue }
            glossary = item
        }

        guard let glossary
        else { throw .invalidMnemonicaVocabulary }

        return (length, glossary)
    }
}

private extension Array where Element == UInt8 {
    init(bitsStringRepresentation string: String) {
        let padded = string.padding(
            toLength: ((string.count + 7) / 8) * 8,
            withPad: "0",
            startingAt: 0
        ).map({ $0 })

        self = stride(from: 0, to: padded.count, by: 8).map({
            let substring = String(padded[$0 ..< $0 + 8])
            guard let byte = UInt8(substring, radix: 2)
            else { fatalError("Couldn't initialize byte from bits string \(substring)") }
            return byte
        })
    }
}
