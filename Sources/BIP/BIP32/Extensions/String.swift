//
//  Created by Anton Spivak
//

extension String {
    var unescaped: String {
        replacingOccurrences(of: "\'", with: "`").replacingOccurrences(of: "'", with: "`")
    }
}
