load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

cc_library(
    name = "vault",
    srcs = [
        "vault.cpp",
    ],
    hdrs = [
       "vault.h",
    ],
    deps = [
        "//vault_storage/proto:vault_cc_proto",
		"//crypto_service:crypto_service",
        "@protobuf//:protobuf",
    ],
	copts = [
		"-std=c++23",
	],
	visibility = [
		"//visibility:public"
	],
)

