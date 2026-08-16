load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

cc_library(
    name = "vault",
    srcs = [
        "vault.cpp",
		"safe_writer.cpp",
		"vault_model.cpp",
		"vault_serializer.cpp",
    ],
    hdrs = [
       "vault.h",
	   "vault_model.hpp",
	   "safe_writer.h",
	   "vault_serializer.h",
    ],
    deps = [
        "//vault_storage/proto:vault_cc_proto",
		"//crypto_service:crypto_service",
		"//master_key_generator:master_key",
        "@protobuf//:protobuf",
    ],
	copts = [
		"-std=c++23",
	],
	visibility = [
		"//visibility:public"
	],
)

