#include "UI/forms/master_form.hpp"
#include <QByteArray>
#include <QMessageBox>
#include <QShowEvent>
#include <sodium.h>
#include <string_view>

namespace {

SecureString toSecureString(const QString &text) {
  QByteArray utf8 = text.toUtf8();
  SecureString secure{std::string_view{
      utf8.constData(), static_cast<std::size_t>(utf8.size())}};
  sodium_memzero(utf8.data(), static_cast<std::size_t>(utf8.size()));
  return secure;
}

} // namespace

MasterForm::MasterForm(QWidget *parent) : QDialog(parent) {
  setWindowTitle("Create master password");
  setModal(true);

  passwordEdit_ = new QLineEdit;
  passwordEdit_->setEchoMode(QLineEdit::Password);
  passwordEdit_->setInputMethodHints(
      Qt::ImhHiddenText | Qt::ImhNoAutoUppercase | Qt::ImhNoPredictiveText |
      Qt::ImhSensitiveData);
  passwordEdit_->setMaxLength(kMasterPasswordMaxLength);
  passwordEdit_->setPlaceholderText("Choose a master password");

  confirmEdit_ = new QLineEdit;
  confirmEdit_->setEchoMode(QLineEdit::Password);
  confirmEdit_->setInputMethodHints(
      Qt::ImhHiddenText | Qt::ImhNoAutoUppercase | Qt::ImhNoPredictiveText |
      Qt::ImhSensitiveData);
  confirmEdit_->setMaxLength(kMasterPasswordMaxLength);
  confirmEdit_->setPlaceholderText("Repeat the master password");

  auto *buttonBox =
      new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);

  auto *layout = new QFormLayout;
  layout->addRow("Password:", passwordEdit_);
  layout->addRow("Confirm:", confirmEdit_);
  layout->addRow(buttonBox);
  setLayout(layout);

  QObject::connect(buttonBox, &QDialogButtonBox::accepted, this,
                   &MasterForm::accept);

  QObject::connect(buttonBox, &QDialogButtonBox::rejected, this,
                   &MasterForm::reject);

  QObject::connect(confirmEdit_, &QLineEdit::returnPressed, this,
                   &MasterForm::accept);
}

SecureString MasterForm::takeSecurePassword() {
  SecureString password = std::move(securePassword_);
  securePassword_ = SecureString{""};
  passwordEdit_->clear();
  confirmEdit_->clear();
  return password;
}

void MasterForm::showEvent(QShowEvent *event) {
  QDialog::showEvent(event);
  passwordEdit_->setFocus();
}

void MasterForm::accept() {
  if (passwordEdit_->text().isEmpty()) {
    QMessageBox::warning(this, "Master password",
                         "The master password must not be empty.");
    passwordEdit_->setFocus();
    return;
  }

  SecureString typed = toSecureString(passwordEdit_->text());
  const SecureString repeated = toSecureString(confirmEdit_->text());

  if (typed != repeated) {
    QMessageBox::warning(this, "Master password",
                         "The two passwords do not match.");
    confirmEdit_->clear();
    confirmEdit_->setFocus();
    return;
  }

  securePassword_ = std::move(typed);
  QDialog::accept();
}

void MasterForm::reject() {
  passwordEdit_->clear();
  confirmEdit_->clear();
  QDialog::reject();
}