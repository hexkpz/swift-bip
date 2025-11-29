//
//  Created by Anton Spivak
//

import Foundation

extension Data {
    init?(hexadecimalString: String) {
        let hexadecimalString = hexadecimalString.hasPrefix("0x")
            ? String(hexadecimalString.dropFirst(2))
            : hexadecimalString

        guard hexadecimalString.count % 2 == 0 else { return nil }

        self.init()
        reserveCapacity(hexadecimalString.count / 2)

        var index = hexadecimalString.startIndex
        while index < hexadecimalString.endIndex {
            let next = hexadecimalString.index(index, offsetBy: 2)
            let byteString = hexadecimalString[index ..< next]

            guard let byte = UInt8(byteString, radix: 16)
            else { return nil }

            append(byte)
            index = next
        }
    }

    var hexadecimalString: String {
        map(\.hexadecimalString).joined(separator: "")
    }
}

extension UInt8 {
    var hexadecimalString: String {
        let value = String(self, radix: 16, uppercase: false)
        return value.count == 1 ? "0\(value)" : value
    }
}
