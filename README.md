# swift-bip

Swift implementation of BIP32, BIP39, BIP44, SLIP0010.

![Platforms](https://img.shields.io/badge/platforms-iOS%20|%20macOS%20|%20tvOS%20|%20watchOS%20|%20Linux-blue)
![Swift](https://img.shields.io/badge/Swift-6.2-orange)

## Installation

```swift
.package(url: "https://github.com/hexkpz/swift-bip.git", .upToNextMajor(from: "0.0.1"))
```

## Ysage

### secp256k1 & BIP32 / BIP39

```swift
import BIP

let mnemonica: Mnemonica = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
let privateKey = try secp256k1.PrivateKey(mnemonica, algorithm: .ethereum(), derivationPath: "m/44'")

try print(privateKey.signature(for: Data("hello".utf8)))
```

### Ed25519 (Curve25519) & SLIP0010 / BIP39

```swift
import BIP

let mnemonica: Mnemonica = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
let privateKey = try Curve25519.Signing.PrivateKey(mnemonica, algorithm: .ton(), derivationPath: "m/44'/607'/0'")

try print(privateKey.signature(for: Data("hello".utf8)))
```

### BIP44

```swift
import BIP

let mnemonica: Mnemonica = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
let privateKey = try Curve25519.Signing.PrivateKey(mnemonica, algorithm: .ethereum(), hdWallet: .init(coin: .ethereum))

try print(privateKey.signature(for: Data("hello".utf8)))
```

## Authors

- hexkpz@gmail.com
