load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
	name = "password_generator",
	srcs = ["pass_gen.cpp"],
	hdrs = ["pass_gen.h"],
	deps = [
		"//master_key_generator:master_key",
	],
	copts = [
		"-std=c++23",
	],
	visibility = [
		"//visibility:public"
	],
	linkopts = [
		"-lsodium",
	],
)
