// swift-tools-version:6.2

import PackageDescription

let package = Package(
    name: "swift-bip",
    platforms: [
        .macOS("10.15"),
        .iOS("13.2"),
        .watchOS("6.1"),
        .tvOS("13.2"),
    ],
    products: [
        .library(name: "BIP", targets: ["BIP"]),
    ],
    dependencies: [
        .package(url: "https://github.com/attaswift/BigInt.git", .upToNextMajor(from: "5.4.1")),
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "3.8.0")),
    ],
    targets: [
        .target(
            name: "BIP",
            dependencies: [
                .product(name: "BigInt", package: "BigInt"),
                .product(name: "Crypto", package: "swift-crypto"),
                .byName(name: "ObscureKit"),
            ],
            path: "Sources/BIP"
        ),
        .testTarget(
            name: "BIPTests",
            dependencies: ["BIP", "ObscureKit"]
        ),
        .target(
            name: "ObscureKit",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),

                .byName(name: "libkeccak"),
                .byName(name: "libsecp256k1"),
            ],
            path: "Sources/ObscureKit"
        ),
        .target(
            name: "libkeccak",
            path: "Sources/libkeccak",
            exclude: [
                "keccak-tiny/do.sh",
                "keccak-tiny/keccak-tiny-unrolled.c",
                "keccak-tiny/README.markdown",
            ],
            sources: ["keccak-tiny"],
            publicHeadersPath: "include"
        ),
        .target(
            name: "libsecp256k1",
            path: "Sources/libsecp256k1",
            sources: [
                "secp256k1/src/secp256k1.c",
                "secp256k1/src/ecmult_const_impl.h",
                "secp256k1/src/ecmult_impl.h",
                "secp256k1/src/precomputed_ecmult.h",
                "secp256k1/src/precomputed_ecmult_gen.h",
                "secp256k1/src/precomputed_ecmult.c",
                "secp256k1/src/precomputed_ecmult_gen.c",
            ],
            publicHeadersPath: "secp256k1/include",
            cSettings: [
                .unsafeFlags(["-Wno-implicit-int-conversion"]),

                .define("SECP256K1_BUILD", to: ""),
                .define("HAVE_CONFIG_H", to: ""),
                .define("ENABLE_MODULE_ECDH"),
                .define("ENABLE_MODULE_RECOVERY"),
                .define("ENABLE_MODULE_EXTRAKEYS"),
                .define("ENABLE_MODULE_SCHNORRSIG"),
                .define("ENABLE_MODULE_ELLSWIFT"),
                .define("ENABLE_MODULE_MUSIG"),
            ]
        ),
    ]
)
