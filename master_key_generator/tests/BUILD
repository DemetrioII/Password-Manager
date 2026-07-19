load("@rules_cc//cc:defs.bzl", "cc_test")

cc_test(
	name = "masterkey_test",
	srcs = ["masterkey_test.cpp"],
	deps = [
		"//master_key_generator:master_key",
		"@googletest//:gtest_main",
	],
	copts = [
		"-std=c++23",
	],
)
