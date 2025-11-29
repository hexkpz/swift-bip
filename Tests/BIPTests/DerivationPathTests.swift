//
//  Created by Anton Spivak
//

import Foundation
import Testing

@testable import BIP

struct DerivationPathTests {
    @Test("Check valid strings", arguments: [
        "m/44`/0/0/0",
        "m/44`/0/0`/0`",
        "m/44`/0/0`/0",
        "m/44`/0`/0/0`/34678/97826364",
    ])
    func checkValidStrings(_ string: String) {
        #expect(BIP32.DerivationPath(string)?.description == string)
    }

    @Test("Check valid strings", arguments: [
        "s/1234567890987654345678909876543456789`/0/0/0",
        "m/44`/0/0\"\"/0`"
    ])
    func checkInvalidStrings(_ string: String) {
        #expect(BIP32.DerivationPath(string)?.description == nil)
    }
}
