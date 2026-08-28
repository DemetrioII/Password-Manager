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

cc_test(
	name = "vault_model_test",
	srcs = ["vault_model_test.cpp"],
	deps = [
		"//vault_storage:vault",
		"@googletest//:gtest_main",
	],
	copts = [
		"-std=c++23",
	],
)

cc_test(
	name = "vault_serializer_test",
	srcs = ["vault_serializer_test.cpp"],
	deps = [
		"//vault_storage:vault",
		"@googletest//:gtest_main",
	],
	copts = [
		"-std=c++23",
	],
)
