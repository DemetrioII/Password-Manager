load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

cc_library(
	name = "master_key",
	srcs = ["masterkey.cpp"],
	hdrs = ["masterkey.h"],
	deps = [
		"@nlohmann_json//:json",
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
