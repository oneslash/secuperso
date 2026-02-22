// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SecuPersoDomain",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .library(
            name: "SecuPersoDomain",
            targets: ["SecuPersoDomain"]
        )
    ],
    targets: [
        .target(
            name: "SecuPersoDomain"
        )
    ]
)
