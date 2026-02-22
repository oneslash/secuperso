// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SecuPersoData",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .library(
            name: "SecuPersoData",
            targets: ["SecuPersoData"]
        )
    ],
    dependencies: [
        .package(path: "../SecuPersoDomain")
    ],
    targets: [
        .target(
            name: "SecuPersoData",
            dependencies: [
                .product(name: "SecuPersoDomain", package: "SecuPersoDomain")
            ],
            linkerSettings: [
                .linkedLibrary("sqlite3")
            ]
        )
    ]
)
