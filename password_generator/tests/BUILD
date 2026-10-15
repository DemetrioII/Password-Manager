load("@rules_cc//cc:defs.bzl", "cc_test")

cc_test(
	name = "pass_gen_test",
	srcs = ["pass_gen_test.cpp"],
	deps = [
		"//password_generator:password_generator",
		"@googletest//:gtest_main",
	],
	copts = [
		"-std=c++23",
	],
)
