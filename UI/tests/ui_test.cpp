// Headless tests for the Qt Widgets dialogs in //UI/forms.
//
// The forms are self-contained QDialogs, so they can be driven without the
// main window: a single QApplication is created for the whole binary (Qt allows
// only one) and every dialog is exercised synchronously on the main thread.
// The QPA platform is pinned to "offscreen" through `env` in the BUILD file, so
// no X server is involved.
//
// No password is ever printed. Assertions compare sizes, character classes or a
// plain boolean, and the two places where contents matter go through view()
// rather than operator== so a failure cannot dump the plaintext into the log.

#include "UI/forms/lock_form.hpp"
#include "UI/forms/password_form.hpp"
#include "master_key_generator/securestring.h"
#include "password_generator/pass_gen.h"

#include <QApplication>
#include <QCheckBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QString>
#include <QStringList>
#include <QTest>

#include <gtest/gtest.h>
#include <sodium.h>

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>

namespace {

class QtEnvironment : public ::testing::Environment {
public:
  void SetUp() override {
    // SecureString allocates through sodium_malloc, which aborts the process
    // when libsodium has not been initialised.
    if (sodium_init() < 0)
      ADD_FAILURE() << "sodium_init() failed";

    static int argc = 1;
    static char program_name[] = "ui_test";
    static char *argv[] = {program_name, nullptr};
    application_ = std::make_unique<QApplication>(argc, argv);
  }

  void TearDown() override { application_.reset(); }

private:
  std::unique_ptr<QApplication> application_;
};

[[maybe_unused]] ::testing::Environment *const kQtEnvironment =
    ::testing::AddGlobalTestEnvironment(new QtEnvironment);

// Character classes of the generator panel, in the order PasswordForm creates
// its check boxes in buildGeneratorPanel(). None of them carries an object
// name, so this order is the only handle on them; classBox() asserts that the
// panel still holds exactly one check box per class, which turns a future
// reordering into a loud failure instead of a silently wrong test.
enum class CharacterClass {
  kLowercase,
  kUppercase,
  kDigits,
  kSymbols,
  kAmbiguous,
};

constexpr std::size_t kCharacterClassCount = 5;

QCheckBox *classBox(QDialog &dialog, CharacterClass which) {
  auto *generator = dialog.findChild<QGroupBox *>("generatorBox");
  if (generator == nullptr)
    return nullptr;

  const QList<QCheckBox *> boxes = generator->findChildren<QCheckBox *>();
  if (static_cast<std::size_t>(boxes.size()) != kCharacterClassCount)
    return nullptr;

  return boxes.at(static_cast<std::size_t>(which));
}

// PasswordForm names neither its line edits nor its generator spin box, so the
// password field is located structurally: it is the QLineEdit sharing a form
// row with the Generate button (the confirm field has a row of its own).
QLineEdit *passwordFieldOf(QDialog &dialog) {
  auto *form = qobject_cast<QFormLayout *>(dialog.layout());
  if (form == nullptr)
    return nullptr;

  for (int row = 0; row < form->rowCount(); ++row) {
    auto *field = form->itemAt(row, QFormLayout::FieldRole);
    if (field == nullptr)
      continue;

    auto *row_layout = field->layout();
    if (row_layout == nullptr)
      continue;

    bool next_to_generate_button = false;
    for (int i = 0; i < row_layout->count(); ++i) {
      const auto *button =
          qobject_cast<const QPushButton *>(row_layout->itemAt(i)->widget());
      if (button != nullptr &&
          button->objectName() == QLatin1String("generateButton")) {
        next_to_generate_button = true;
        break;
      }
    }
    if (!next_to_generate_button)
      continue;

    for (int i = 0; i < row_layout->count(); ++i) {
      if (auto *edit =
              qobject_cast<QLineEdit *>(row_layout->itemAt(i)->widget()))
        return edit;
    }
  }
  return nullptr;
}

} // namespace

// --- PasswordForm, add mode -------------------------------------------------

TEST(PasswordFormAdd, ExposesAGenerateButtonNextToThePasswordField) {
  PasswordForm form;

  auto *generate = form.findChild<QPushButton *>("generateButton");
  ASSERT_NE(generate, nullptr);
  EXPECT_TRUE(generate->isEnabled());

  auto *password_field = passwordFieldOf(form);
  ASSERT_NE(password_field, nullptr);
  EXPECT_EQ(password_field->echoMode(), QLineEdit::Password);
}

TEST(PasswordFormAdd, GenerateProducesAPasswordOfTheSpinBoxLength) {
  PasswordForm form;
  auto *generate = form.findChild<QPushButton *>("generateButton");
  auto *length = form.findChild<QSpinBox *>();
  auto *password_field = passwordFieldOf(form);
  ASSERT_NE(generate, nullptr);
  ASSERT_NE(length, nullptr);
  ASSERT_NE(password_field, nullptr);

  length->setValue(24);
  ASSERT_EQ(length->value(), 24);

  generate->click();

  const QString generated = password_field->text();
  EXPECT_FALSE(generated.isEmpty());
  EXPECT_EQ(generated.size(), 24);
}

TEST(PasswordFormAdd, CheckedClassesDecideTheGeneratedAlphabet) {
  PasswordForm form;
  auto *generate = form.findChild<QPushButton *>("generateButton");
  auto *length = form.findChild<QSpinBox *>();
  auto *password_field = passwordFieldOf(form);
  auto *lowercase = classBox(form, CharacterClass::kLowercase);
  auto *uppercase = classBox(form, CharacterClass::kUppercase);
  auto *digits = classBox(form, CharacterClass::kDigits);
  auto *symbols = classBox(form, CharacterClass::kSymbols);
  ASSERT_NE(generate, nullptr);
  ASSERT_NE(length, nullptr);
  ASSERT_NE(password_field, nullptr);
  ASSERT_NE(lowercase, nullptr);
  ASSERT_NE(uppercase, nullptr);
  ASSERT_NE(digits, nullptr);
  ASSERT_NE(symbols, nullptr);

  // Digits only.
  lowercase->setChecked(false);
  uppercase->setChecked(false);
  symbols->setChecked(false);
  digits->setChecked(true);
  length->setValue(20);

  generate->click();

  const QString generated = password_field->text();
  ASSERT_EQ(generated.size(), 20);

  const QString digits_alphabet{
      std::string{PasswordGenerator::kDigits}.c_str()};
  for (qsizetype i = 0; i < generated.size(); ++i) {
    // Only the index is reported, never the character itself.
    EXPECT_TRUE(digits_alphabet.contains(generated.at(i)))
        << "non-digit character at index " << i;
  }
}

TEST(PasswordFormAdd, TakeSecurePasswordHandsOverAndScrubsTheField) {
  PasswordForm form;
  auto *generate = form.findChild<QPushButton *>("generateButton");
  auto *password_field = passwordFieldOf(form);
  ASSERT_NE(generate, nullptr);
  ASSERT_NE(password_field, nullptr);

  generate->click();
  const qsizetype generated_length = password_field->text().size();
  ASSERT_GT(generated_length, 0);

  SecureString taken = form.takeSecurePassword();
  EXPECT_FALSE(taken.empty());
  EXPECT_EQ(taken.size(), static_cast<std::size_t>(generated_length));

  EXPECT_TRUE(password_field->text().isEmpty());
  // The hand-over is destructive: a second call yields an empty secret.
  EXPECT_TRUE(form.takeSecurePassword().empty());
}

TEST(PasswordFormAdd, TypedPasswordIsMirroredIntoTheSecureBuffer) {
  PasswordForm form;
  auto *password_field = passwordFieldOf(form);
  ASSERT_NE(password_field, nullptr);

  const QString typed = QStringLiteral("hand-written-entry");
  QTest::keyClicks(password_field, typed);
  ASSERT_FALSE(password_field->text().isEmpty());

  // The mirror is refreshed from the textEdited() signal, so only real key
  // events get the buffer into sync with the field.
  SecureString taken = form.takeSecurePassword();
  EXPECT_EQ(taken.size(), static_cast<std::size_t>(typed.size()));
  EXPECT_TRUE(password_field->text().isEmpty());
}

// --- LockForm ---------------------------------------------------------------

TEST(LockForm, SetErrorShowsAndHidesTheInlineMessage) {
  LockForm form;
  auto *error_label = form.findChild<QLabel *>("errorLabel");
  ASSERT_NE(error_label, nullptr);
  ASSERT_TRUE(error_label->isHidden());

  form.setError(QStringLiteral("Wrong password."));
  EXPECT_EQ(error_label->text().toStdString(),
            std::string("Wrong password."));
  EXPECT_FALSE(error_label->isHidden());

  form.setError(QString{});
  EXPECT_TRUE(error_label->isHidden());
}

TEST(LockForm, CancelRejectsTheDialogAndClearsTheTypedPassword) {
  LockForm form;
  auto *password_field = form.findChild<QLineEdit *>();
  auto *buttons = form.findChild<QDialogButtonBox *>();
  ASSERT_NE(password_field, nullptr);
  ASSERT_NE(buttons, nullptr);

  QTest::keyClicks(password_field, QStringLiteral("half-typed-secret"));
  ASSERT_FALSE(password_field->text().isEmpty());

  auto *cancel = buttons->button(QDialogButtonBox::Cancel);
  ASSERT_NE(cancel, nullptr);
  cancel->click();

  EXPECT_EQ(form.result(), QDialog::Rejected);
  EXPECT_TRUE(password_field->text().isEmpty());
}

TEST(LockForm, TakeSecurePasswordIsEmptyWhenNothingWasTyped) {
  LockForm form;

  SecureString taken = form.takeSecurePassword();
  EXPECT_TRUE(taken.empty());
  EXPECT_EQ(taken.size(), std::size_t{0});
}

TEST(LockForm, TakeSecurePasswordMatchesTheInputAndScrubsTheField) {
  LockForm form;
  auto *password_field = form.findChild<QLineEdit *>();
  ASSERT_NE(password_field, nullptr);

  const QString typed = QStringLiteral("unlock-me-please");
  QTest::keyClicks(password_field, typed);
  ASSERT_FALSE(password_field->text().isEmpty());

  SecureString taken = form.takeSecurePassword();
  EXPECT_EQ(taken.size(), static_cast<std::size_t>(typed.size()));
  // Reported as a bare bool on purpose: an EXPECT_EQ on the buffer contents
  // would write the master password into the test log.
  const std::string expected = typed.toStdString();
  EXPECT_TRUE(taken.view() == std::string_view{expected});
  EXPECT_TRUE(password_field->text().isEmpty());
}