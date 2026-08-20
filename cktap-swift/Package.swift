// swift-tools-version:5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "cktap-swift",
    platforms: [
        .macOS(.v12),
        .iOS("18.0")
    ],
    products: [
        .library(
            name: "CKTap",
            targets: ["cktapFFI", "CKTap"]),
    ],
    dependencies: [],
    targets: [
        .binaryTarget(
            name: "cktapFFI", 
            path: "./cktapFFI.xcframework"),
        .target(
            name: "CKTap",
            dependencies: ["cktapFFI"]
        ),
        .testTarget(
            name: "CKTapTests",
            dependencies: ["CKTap"]
        )
    ]
)
