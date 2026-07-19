load("@rules_cc//cc:defs.bzl", "cc_test", "cc_library")

cc_test(
	name = "crypto_test",
	srcs = ["crypto_test.cpp"],
	deps = [
		"//crypto_service:crypto_service",
		"@googletest//:gtest_main",
	],
	copts = [
		"-std=c++23",
	],
)
