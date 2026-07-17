load("@protobuf//bazel:proto_library.bzl", "proto_library")
load("@protobuf//bazel:cc_proto_library.bzl", "cc_proto_library")

proto_library(
    name = "vault_proto",
    srcs = ["vault.proto"],
	visibility = ["//visibility:public"],
)

cc_proto_library(
    name = "vault_cc_proto",
    deps = [":vault_proto"],
	visibility = ["//visibility:public"],
)
