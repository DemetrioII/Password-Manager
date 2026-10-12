#include "UI/forms/lock_form.hpp"

LockForm::LockForm(QWidget *parent) : QDialog(parent) {
  setWindowTitle("Unlock Vault");
  setModal(true);

  auto *layout = new QFormLayout;

  passwordEdit_ = new QLineEdit;
  passwordEdit_->setEchoMode(QLineEdit::Password);
  passwordEdit_->setInputMethodHints(
      Qt::ImhHiddenText | Qt::ImhNoAutoUppercase | Qt::ImhNoPredictiveText |
      Qt::ImhSensitiveData);
  passwordEdit_->setPlaceholderText("Enter your master password");

  QDialogButtonBox *buttonBox =
      new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);

  QObject::connect(buttonBox, &QDialogButtonBox::accepted, this,
                   &QDialog::accept);

  QObject::connect(buttonBox, &QDialogButtonBox::rejected, this,
                   &QDialog::reject);

  layout->addRow("Password:", passwordEdit_);
  layout->addRow(buttonBox);
  setLayout(layout);
}

QString LockForm::getPassword() const {
  return passwordEdit_->text();
}

SecureString LockForm::takeSecurePassword() {
  SecureString s{passwordEdit_->text().toStdString()};
  passwordEdit_->clear();
  return s;
}

void LockForm::clearSensitiveFields() {
  passwordEdit_->clear();
}
