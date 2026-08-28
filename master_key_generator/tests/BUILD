load("@rules_cc//cc:defs.bzl", "cc_test")

cc_test(
    name = "securestring_test",
    srcs = ["securestring_test.cpp"],
    deps = [
        "//master_key_generator:master_key",
        "@googletest//:gtest_main",
    ],
    copts = [
        "-std=c++23",
    ]
)

cc_test(
	name = "masterkey_test",
	srcs = ["masterkey_test.cpp"],
	deps = [
		"//master_key_generator:master_key",
		"@googletest//:gtest_main",
	],
	copts = [
		"-std=c++23",
	],
)

cc_test(
    name = "ephemeralkey_test",
    srcs = ["ephemeralkey_test.cpp"],
    deps = [
        "//master_key_generator:master_key",
        "@googletest//:gtest_main",
    ],
    copts = [
        "-std=c++23",
    ],
)

cc_test(
    name = "encryptedfield_test",
    srcs = ["encryptedfield_test.cpp"],
    deps = [
        "//master_key_generator:master_key",
        "@googletest//:gtest_main",
    ],
    copts = [
        "-std=c++23",
    ],
)

cc_test(
    name = "nonce_test",
    srcs = ["nonce_test.cpp"],
    deps = [
        "//master_key_generator:master_key",
        "@googletest//:gtest_main",
    ],
    copts = [
        "-std=c++23",
    ],
)

cc_test(
    name = "salt_test",
    srcs = ["salt_test.cpp"],
    deps = [
        "//master_key_generator:master_key",
        "@googletest//:gtest_main",
    ],
    copts = [
        "-std=c++23",
    ],
)
