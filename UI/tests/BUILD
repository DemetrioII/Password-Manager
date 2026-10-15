load("@rules_cc//cc:defs.bzl", "cc_test")

# Headless Qt Widgets tests for the dialog forms.
#
# rules_qt has no qt_cc_test, and the forms are a plain qt_cc_library, so this is
# an ordinary cc_test linked against @qt//:Qt*. The QPA platform is forced to
# "offscreen" (see `env`) because the machine has no X server; the plugin lives
# next to the system Qt in /usr/lib/<triple>/qt6/plugins/platforms.
#
# The Qt shared libraries themselves come from @qt// as runfiles, so no
# LD_LIBRARY_PATH juggling is needed.
cc_test(
    name = "ui_test",
    srcs = ["ui_test.cpp"],
    copts = [
        "-std=c++23",
        # The Qt toolchain is only used by the qt_* rules, so a plain cc_test
        # misses the module defines that QtTest's own headers gate the widget
        # helpers (QTest::keyClicks and friends) behind.
        "-DQT_GUI_LIB",
        "-DQT_WIDGETS_LIB",
    ],
    deps = [
        "//UI/forms:forms",
        "//vault_storage:vault",
        "@googletest//:gtest_main",
        "@qt//:QtTest",
        "@qt//:QtWidgets",
    ],
    env = {
        "QT_QPA_PLATFORM": "offscreen",
    },
    size = "small",
)