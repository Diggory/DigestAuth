// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "DigestAuth",
	
	platforms: [
		.macOS(.v10_15),
		],

	
	dependencies: [
		.package(url: "https://github.com/apple/swift-crypto.git", from: "2.0.0"),
		.package(url: "https://github.com/swift-server/async-http-client", from: "1.19.0")
	],
	
    targets: [
        .executableTarget(
            name: "DigestAuth",
			dependencies: [
				.product(name: "AsyncHTTPClient", package: "async-http-client"),
				.product(name: "Crypto", package: "swift-crypto")
			]
		),
    ]
)
