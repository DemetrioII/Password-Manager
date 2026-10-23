#include "UI/forms/master_form.hpp"
#include "UI/forms/cipher_names.hpp"
#include "UI/forms/secure_input.hpp"
#include <QMessageBox>
#include <QShowEvent>

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
  passwordEdit_->setObjectName("passwordEdit");

  confirmEdit_ = new QLineEdit;
  confirmEdit_->setEchoMode(QLineEdit::Password);
  confirmEdit_->setInputMethodHints(
      Qt::ImhHiddenText | Qt::ImhNoAutoUppercase | Qt::ImhNoPredictiveText |
      Qt::ImhSensitiveData);
  confirmEdit_->setMaxLength(kMasterPasswordMaxLength);
  confirmEdit_->setPlaceholderText("Repeat the master password");
  confirmEdit_->setObjectName("confirmEdit");

  cipherBox_ = new QComboBox;
  cipherBox_->setObjectName("cipherBox");
  // Item data carries the algorithm id, so the caller reads an enum instead of
  // counting rows and a relabelled item cannot be mistaken for another cipher.
  cipherBox_->addItem(
      QStringLiteral("%1 (recommended, default)")
          .arg(cipherDisplayName(
              vault::CipherAlgorithm::XChaCha20Poly1305)),
      static_cast<int>(vault::CipherAlgorithm::XChaCha20Poly1305));
  cipherBox_->addItem(
      cipherDisplayName(vault::CipherAlgorithm::ChaCha20Poly1305),
      static_cast<int>(vault::CipherAlgorithm::ChaCha20Poly1305));
  cipherBox_->setToolTip(
      "Both ciphers seal the vault with a Poly1305 tag. XChaCha20-Poly1305 "
      "takes its nonce from 24 random bytes instead of 12.");

  auto *buttonBox =
      new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);

  auto *layout = new QFormLayout;
  layout->addRow("Password:", passwordEdit_);
  layout->addRow("Confirm:", confirmEdit_);
  layout->addRow("Cipher:", cipherBox_);
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

vault::CipherAlgorithm MasterForm::cipher() const noexcept {
  return static_cast<vault::CipherAlgorithm>(cipherBox_->currentData().toInt());
}

void MasterForm::selectCipher(vault::CipherAlgorithm cipher) {
  const int row = cipherBox_->findData(static_cast<int>(cipher));
  // An id this build does not know leaves the recommended selection in place,
  // rather than a row the form would then report back as the chosen cipher.
  if (row >= 0)
    cipherBox_->setCurrentIndex(row);
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