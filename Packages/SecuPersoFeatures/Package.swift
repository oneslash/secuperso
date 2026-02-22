// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SecuPersoFeatures",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .library(
            name: "SecuPersoFeatures",
            targets: ["SecuPersoFeatures"]
        )
    ],
    dependencies: [
        .package(path: "../SecuPersoDomain"),
        .package(path: "../SecuPersoUI")
    ],
    targets: [
        .target(
            name: "SecuPersoFeatures",
            dependencies: [
                .product(name: "SecuPersoDomain", package: "SecuPersoDomain"),
                .product(name: "SecuPersoUI", package: "SecuPersoUI")
            ]
        )
    ]
)
