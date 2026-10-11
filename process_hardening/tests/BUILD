load("@rules_cc//cc:defs.bzl", "cc_test")

cc_test(
    name = "process_hardening_test",
    srcs = ["process_hardening_test.cpp"],
    deps = [
        "//process_hardening:process_hardening",
        "@googletest//:gtest_main",
    ],
    copts = [
        "-std=c++23",
    ],
)