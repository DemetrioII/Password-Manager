load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

cc_binary(
	name = "app",
	srcs = ["main.cpp"],
	copts = [
		"-std=c++23",
	],
	deps = [
		"//crypto_service:crypto_service",
		"//master_key_generator:master_key",
		"//vault_storage:vault",
	],
)
