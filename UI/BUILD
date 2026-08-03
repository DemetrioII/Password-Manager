load("@rules_qt//qt:defs.bzl", "qt_cc_binary", "qt_cc_moc", "qt_cc_moc_import", "qt_qrc", "qt_cc_rcc")

qt_cc_moc(
	name = "moc_hdrs",
	hdrs = ["UI.hpp",],
)

qt_cc_moc_import(
	name = "moc_srcs",
	srcs = [
		"UI.cpp",
	],
)

qt_qrc(
	name = "qrc",
	srcs = [".qrc"],
	data = ["dark.qss"],
)

qt_cc_rcc(
	name = "resources",
	srcs = [":qrc"],
)

qt_cc_binary(
    name = "UI",
    srcs = [
        "UI.cpp",
    ],
	moc_hdrs = ["UI.hpp"],
	moc_srcs = ["main.cpp"],
	qrc_srcs = [":qrc"],
	copts = [
		"-std=c++23",
	],
    deps = [
        "@qt//:QtWidgets",
		"//vault_storage:vault",
    ],
)
