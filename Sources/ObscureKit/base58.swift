//
//  Created by Anton Spivak
//

import Foundation
import Crypto

public extension Data {
    struct Base58DecondingOptions: OptionSet, Sendable {
        // MARK: Lifecycle

        public init(rawValue: UInt) {
            self.rawValue = rawValue
        }

        // MARK: Public

        public static let checkCheksum = Self(rawValue: 1 << 0)

        public var rawValue: UInt
    }

    init?(base58Encoded value: String, options: Base58DecondingOptions = []) {
        guard var data = base58Decode(value) else { return nil }

        if options.contains(.checkCheksum) {
            guard data.count >= 4 else { return nil }

            let checksum = data[data.count - 4 ..< data.count]
            data = data[0 ..< data.count - 4]

            guard data.sha256.sha256[0 ..< 4] == checksum else { return nil }
        }

        self = data
    }
}

public extension Data {
    struct Base58EncodingOptions: OptionSet, Sendable {
        // MARK: Lifecycle

        public init(rawValue: UInt) {
            self.rawValue = rawValue
        }

        // MARK: Public

        public static let includeChecksum = Self(rawValue: 1 << 0)

        public var rawValue: UInt
    }

    var base58EncodedString: String {
        guard !isEmpty else { return "" }
        return base58Encode(self)
    }

    func base58EncodedString(with options: Base58EncodingOptions) -> String {
        guard !isEmpty else { return "" }

        var data = self
        if options.contains(.includeChecksum) {
            let checksum = sha256.sha256[0 ..< 4]
            data.append(contentsOf: checksum)
        }

        return base58Encode(data)
    }
}

private let alphabet = [Character]("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
private let indexes: [Character: Int] = {
    var result = [Character: Int](minimumCapacity: alphabet.count)
    for (index, char) in alphabet.enumerated() {
        result[char] = index
    }
    return result
}()

// MARK: - base58

func base58Encode(_ data: Data) -> String {
    let bytes = [UInt8](data)

    guard !bytes.isEmpty
    else { return "" }

    var zeros = 0
    while zeros < bytes.count, bytes[zeros] == 0 {
        zeros &+= 1
    }

    var input = bytes
    var startIndex = zeros

    var encoded = [Character]()
    encoded.reserveCapacity(bytes.count * 2)

    while startIndex < input.count {
        var carry = 0

        var i = startIndex
        while i < input.count {
            let value = Int(input[i]) &+ (carry << 8)
            let quotient = value / 58

            carry = value % 58
            input[i] = UInt8(quotient)

            if quotient == 0, i == startIndex { startIndex &+= 1 }
            i &+= 1
        }

        encoded.append(alphabet[carry])
    }

    while zeros > 0 {
        encoded.append(alphabet[0])
        zeros &-= 1
    }

    return String(encoded.reversed())
}

func base58Decode(_ string: String) -> Data? {
    guard !string.isEmpty else { return nil }

    var zeros = 0
    var seenNonZero = false
    for char in string {
        if char == alphabet[0], !seenNonZero {
            zeros &+= 1
        } else {
            seenNonZero = true
        }
    }

    var output = [UInt8]()
    output.reserveCapacity(string.count)

    for char in string {
        guard let digit = indexes[char]
        else { return nil }

        var carry = digit

        var i = output.count - 1
        while i >= 0 {
            let value = Int(output[i]) * 58 + carry
            output[i] = UInt8(truncatingIfNeeded: value & 0xFF)
            carry = value >> 8

            if i == 0 { break }
            i &-= 1
        }

        while carry > 0 {
            output.insert(UInt8(truncatingIfNeeded: carry & 0xFF), at: 0)
            carry >>= 8
        }
    }

    var firstNonZeroIndex = 0
    while firstNonZeroIndex < output.count, output[firstNonZeroIndex] == 0 {
        firstNonZeroIndex &+= 1
    }

    var result = [UInt8](repeating: 0, count: zeros)
    result.append(contentsOf: output[firstNonZeroIndex ..< output.count])

    return Data(result)
}
