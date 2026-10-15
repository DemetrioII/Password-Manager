#include "UI/forms/lock_form.hpp"
#include <QByteArray>
#include <QShowEvent>
#include <sodium.h>
#include <string_view>

LockForm::LockForm(QWidget *parent) : QDialog(parent) {
  setWindowTitle("Unlock vault");
  setModal(true);

  passwordEdit_ = new QLineEdit;
  passwordEdit_->setEchoMode(QLineEdit::Password);
  passwordEdit_->setInputMethodHints(
      Qt::ImhHiddenText | Qt::ImhNoAutoUppercase | Qt::ImhNoPredictiveText |
      Qt::ImhSensitiveData);
  passwordEdit_->setMaxLength(kMasterPasswordMaxLength);
  passwordEdit_->setPlaceholderText("Enter your master password");

  errorLabel_ = new QLabel;
  errorLabel_->setObjectName("errorLabel");
  errorLabel_->setWordWrap(true);
  errorLabel_->hide();

  QDialogButtonBox *buttonBox =
      new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);

  auto *layout = new QFormLayout;
  layout->addRow("Password:", passwordEdit_);
  layout->addRow(errorLabel_);
  layout->addRow(buttonBox);
  setLayout(layout);

  QObject::connect(buttonBox, &QDialogButtonBox::accepted, this,
                   &QDialog::accept);

  QObject::connect(buttonBox, &QDialogButtonBox::rejected, this,
                   &QDialog::reject);

  QObject::connect(passwordEdit_, &QLineEdit::returnPressed, this,
                   &QDialog::accept);
}

SecureString LockForm::takeSecurePassword() {
  QByteArray utf8 = passwordEdit_->text().toUtf8();
  SecureString password{std::string_view{
      utf8.constData(), static_cast<std::size_t>(utf8.size())}};
  sodium_memzero(utf8.data(), static_cast<std::size_t>(utf8.size()));
  passwordEdit_->clear();
  return password;
}

void LockForm::setError(const QString &message) {
  errorLabel_->setText(message);
  errorLabel_->setVisible(!message.isEmpty());
}

void LockForm::showEvent(QShowEvent *event) {
  QDialog::showEvent(event);
  passwordEdit_->setFocus();
}

void LockForm::reject() {
  passwordEdit_->clear();
  QDialog::reject();
}