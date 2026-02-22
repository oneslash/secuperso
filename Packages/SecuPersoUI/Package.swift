// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SecuPersoUI",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .library(
            name: "SecuPersoUI",
            targets: ["SecuPersoUI"]
        )
    ],
    dependencies: [
        .package(path: "../SecuPersoDomain")
    ],
    targets: [
        .target(
            name: "SecuPersoUI",
            dependencies: [
                .product(name: "SecuPersoDomain", package: "SecuPersoDomain")
            ]
        )
    ]
)
