
load("@rules_qt//qt:defs.bzl", "qt_cc_binary", "qt_cc_moc", "qt_cc_moc_import", "qt_qrc", "qt_cc_library")

qt_cc_moc(
	name = "forms_moc_hdrs",
	hdrs = ["password_form.hpp",
		 "save_form.hpp",
		 "load_form.hpp",
		 "lock_form.hpp"
		],
)

qt_cc_moc_import(
	name = "forms_moc_srcs",
	srcs = [
		"password_form.cpp",
		"save_form.cpp",
		"load_form.cpp",
		"lock_form.cpp",
	],
)

qt_cc_library(
	name = "forms",
	moc_hdrs = ["password_form.hpp",
				"save_form.hpp",
				"load_form.hpp",
				"lock_form.hpp"],
	moc_srcs = ["password_form.cpp",
				"save_form.cpp",
				"load_form.cpp",
				"lock_form.cpp"],
	copts = [
		"-std=c++23",
	],
    deps = [
        "@qt//:QtWidgets",
		"//vault_storage:vault",
    ],
	visibility = [
		"//visibility:public",
	],
)
