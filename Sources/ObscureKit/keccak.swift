//
//  Created by Anton Spivak
//

import Foundation
import libkeccak

public func keccak256<D>(_ value: D) -> Data where D: DataProtocol {
    var inputValue = [UInt8](value)
    var outputValue = [UInt8](repeating: 0, count: 32)
    _ = keccack_256(&outputValue, outputValue.count, &inputValue, inputValue.count)
    return Data(outputValue)
}
