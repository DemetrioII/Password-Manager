load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")
# load("@drogon//:drogon.bzl", "drogon_cc_library")

cc_library(
	name = "crypto_service",
	srcs = ["crypto.cpp"],
	hdrs = ["crypto.h"],
	deps = [
		"//master_key_generator:master_key",
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
