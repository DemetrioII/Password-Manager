load("@rules_cc//cc:defs.bzl", "cc_test")

cc_test(
	name = "vault_test",
	srcs = ["vault_test.cpp"],
	deps = [
		"//vault_storage:vault",
		"@googletest//:gtest_main",
	],
	copts = [
		"-std=c++23",
	],
)
