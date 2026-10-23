#include "UI/forms/password_form.hpp"
#include "UI/forms/secure_input.hpp"
#include "password_generator/pass_gen.h"
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGridLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QVBoxLayout>

namespace {

QString describePasswordError(PasswordError error) {
  switch (error) {
  case PasswordError::NoCharacterClass:
    return "Select at least one character class (lower case, upper case, "
           "digits or symbols).";
  case PasswordError::LengthTooShort:
    return "The requested length is shorter than the number of enabled "
           "character classes.";
  case PasswordError::LengthTooLong:
    return "The requested length exceeds the maximum supported length.";
  case PasswordError::AllocationFailed:
    return "The password buffer could not be allocated.";
  }
  return "The password could not be generated.";
}

} // namespace

PasswordForm::PasswordForm(QWidget *parent) : QDialog(parent) {
  setWindowTitle("New entry");
  setModal(true);
  resize(460, 380);

  titleEdit = new QLineEdit;
  titleEdit->setMaxLength(MAX_TITLE_SIZE);
  titleEdit->setPlaceholderText("What is this entry for?");

  loginEdit = new QLineEdit;
  loginEdit->setMaxLength(MAX_LOGIN_SIZE);
  loginEdit->setPlaceholderText("Username or e-mail");

  passwordEdit = new QLineEdit;
  passwordEdit->setEchoMode(QLineEdit::Password);
  passwordEdit->setMaxLength(kManualPasswordMaxLength);
  passwordEdit->setInputMethodHints(
      Qt::ImhHiddenText | Qt::ImhNoAutoUppercase | Qt::ImhNoPredictiveText |
      Qt::ImhSensitiveData);

  confirmEdit = new QLineEdit;
  confirmEdit->setEchoMode(QLineEdit::Password);
  confirmEdit->setMaxLength(kManualPasswordMaxLength);
  confirmEdit->setInputMethodHints(
      Qt::ImhHiddenText | Qt::ImhNoAutoUppercase | Qt::ImhNoPredictiveText |
      Qt::ImhSensitiveData);
  confirmEdit->setPlaceholderText("Repeat the password");

  buildGeneratorPanel();

  auto *generateButton = new QPushButton("Generate");
  generateButton->setObjectName("generateButton");

  auto *passwordRow = new QHBoxLayout;
  passwordRow->addWidget(passwordEdit);
  passwordRow->addWidget(generateButton);

  auto *layout = new QFormLayout;
  layout->addRow("Title:", titleEdit);
  layout->addRow("Login:", loginEdit);
  layout->addRow("Password:", passwordRow);
  layout->addRow("Confirm:", confirmEdit);
  layout->addRow(generatorBox);
  setLayout(layout);

  auto *buttonBox =
      new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
  layout->addRow(buttonBox);

  QObject::connect(generateButton, &QPushButton::clicked, this,
                   &PasswordForm::generatePassword);

  QObject::connect(passwordEdit, &QLineEdit::textEdited, this,
                   [this](const QString &) { syncSecureBuffer(); });

  QObject::connect(buttonBox, &QDialogButtonBox::accepted, this,
                   &PasswordForm::accept);

  QObject::connect(buttonBox, &QDialogButtonBox::rejected, this,
                   &QDialog::reject);

  QObject::connect(confirmEdit, &QLineEdit::returnPressed, this,
                   &PasswordForm::accept);
}

PasswordForm::PasswordForm(const vault::PasswordEntry &entry,
                           const vault::Vault &vault, QWidget *parent)
    : QDialog(parent) {
  setWindowTitle("Edit entry");
  setModal(true);
  resize(460, 380);

  titleEdit = new QLineEdit;
  titleEdit->setMaxLength(MAX_TITLE_SIZE);

  loginEdit = new QLineEdit;
  loginEdit->setMaxLength(MAX_LOGIN_SIZE);

  passwordEdit = new QLineEdit;
  passwordEdit->setEchoMode(QLineEdit::Password);
  passwordEdit->setMaxLength(kManualPasswordMaxLength);
  passwordEdit->setInputMethodHints(
      Qt::ImhHiddenText | Qt::ImhNoAutoUppercase | Qt::ImhNoPredictiveText |
      Qt::ImhSensitiveData);

  confirmEdit = nullptr;

  titleEdit->setText(QString::fromStdString(entry.title));
  loginEdit->setText(QString::fromStdString(entry.login));

  const auto password = vault.ShowPassword(entry.id);
  if (!password) {
    QMessageBox::warning(
        parent, "Error",
        "The password of this entry could not be decrypted. The entry was "
        "not opened for editing.");
    reject();
    return;
  }

  const auto view = password->view();
  passwordEdit->setText(
      QString::fromUtf8(view.data(), static_cast<qsizetype>(view.size())));
  syncSecureBuffer();

  buildGeneratorPanel();

  auto *generateButton = new QPushButton("Generate");
  generateButton->setObjectName("generateButton");

  auto *passwordRow = new QHBoxLayout;
  passwordRow->addWidget(passwordEdit);
  passwordRow->addWidget(generateButton);

  auto *layout = new QFormLayout;
  layout->addRow("Title:", titleEdit);
  layout->addRow("Login:", loginEdit);
  layout->addRow("Password:", passwordRow);
  layout->addRow(generatorBox);
  setLayout(layout);

  auto *buttonBox =
      new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
  layout->addRow(buttonBox);

  QObject::connect(generateButton, &QPushButton::clicked, this,
                   &PasswordForm::generatePassword);

  QObject::connect(passwordEdit, &QLineEdit::textEdited, this,
                   [this](const QString &) { syncSecureBuffer(); });

  QObject::connect(buttonBox, &QDialogButtonBox::accepted, this,
                   &PasswordForm::accept);

  QObject::connect(buttonBox, &QDialogButtonBox::rejected, this,
                   &QDialog::reject);
}

SecureString PasswordForm::takeSecurePassword() {
  SecureString password = std::move(securePassword);
  securePassword = SecureString{""};
  clearSensitiveFields();
  return password;
}

void PasswordForm::clearSensitiveFields() {
  passwordEdit->clear();
  if (confirmEdit)
    confirmEdit->clear();
  securePassword = SecureString{""};
}

void PasswordForm::accept() {
  if (titleEdit->text().trimmed().isEmpty()) {
    QMessageBox::warning(this, "New entry", "The title must not be empty.");
    titleEdit->setFocus();
    return;
  }

  if (loginEdit->text().trimmed().isEmpty()) {
    QMessageBox::warning(this, "New entry", "The login must not be empty.");
    loginEdit->setFocus();
    return;
  }

  if (passwordEdit->text().isEmpty()) {
    QMessageBox::warning(this, "New entry", "The password must not be empty.");
    passwordEdit->setFocus();
    return;
  }

  if (confirmEdit && confirmEdit->text() != passwordEdit->text()) {
    QMessageBox::warning(this, "New entry",
                         "The two passwords do not match.");
    confirmEdit->clear();
    confirmEdit->setFocus();
    return;
  }

  syncSecureBuffer();
  QDialog::accept();
}

void PasswordForm::buildGeneratorPanel() {
  generatorBox = new QGroupBox("Generator");
  generatorBox->setObjectName("generatorBox");

  lengthSpin = new QSpinBox;
  lengthSpin->setRange(static_cast<int>(PasswordGenerator::kMinLength),
                       static_cast<int>(PasswordGenerator::kMaxLength));
  lengthSpin->setValue(static_cast<int>(PasswordPolicy{}.length));

  lowercaseBox = new QCheckBox("a-z");
  uppercaseBox = new QCheckBox("A-Z");
  digitsBox = new QCheckBox("0-9");
  symbolsBox = new QCheckBox("symbols");
  ambiguousBox = new QCheckBox("exclude ambiguous (0/O/o, 1/l/I)");

  const PasswordPolicy defaults;
  lowercaseBox->setChecked(defaults.lowercase);
  uppercaseBox->setChecked(defaults.uppercase);
  digitsBox->setChecked(defaults.digits);
  symbolsBox->setChecked(defaults.symbols);
  ambiguousBox->setChecked(defaults.exclude_ambiguous);

  auto *classes = new QGridLayout;
  classes->addWidget(lowercaseBox, 0, 0);
  classes->addWidget(uppercaseBox, 0, 1);
  classes->addWidget(digitsBox, 0, 2);
  classes->addWidget(symbolsBox, 0, 3);
  classes->addWidget(ambiguousBox, 1, 0, 1, 4);
  classes->setColumnStretch(4, 1);

  auto *layout = new QFormLayout(generatorBox);
  layout->addRow("Length:", lengthSpin);
  layout->addRow(classes);
}

void PasswordForm::generatePassword() {
  PasswordPolicy policy;
  policy.length = static_cast<std::size_t>(lengthSpin->value());
  policy.lowercase = lowercaseBox->isChecked();
  policy.uppercase = uppercaseBox->isChecked();
  policy.digits = digitsBox->isChecked();
  policy.symbols = symbolsBox->isChecked();
  policy.exclude_ambiguous = ambiguousBox->isChecked();

  auto generated = PasswordGenerator::generate(policy);
  if (!generated) {
    QMessageBox::warning(this, "Generator",
                         describePasswordError(generated.error()));
    return;
  }

  const auto view = generated->view();
  passwordEdit->setText(
      QString::fromUtf8(view.data(), static_cast<qsizetype>(view.size())));

  // setText() does not emit textEdited, so the mirror is updated by hand. The
  // generated buffer is moved, never copied through a QString again.
  securePassword = std::move(*generated);

  if (confirmEdit)
    confirmEdit->clear();

  passwordEdit->setFocus();
}

void PasswordForm::syncSecureBuffer() {
  securePassword = toSecureString(passwordEdit->text());
}