#pragma once
#include "UI/forms/lock_form.hpp"
#include "master_key_generator/securestring.h"
#include "vault_storage/vault_model.hpp"
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLineEdit>
#include <QWidget>

// Master password prompt with a mandatory confirmation field, used when a new
// vault is created. The confirmation never leaves this dialog: it is compared
// against the first field and then dropped.
//
// The cipher picker lives here as well: the master password and the cipher are
// the two decisions that exist exactly once per vault, and this dialog is
// already re-opened for every creation attempt (the startup flow loops when a
// save fails), so a retried creation keeps the choice through selectCipher().
class MasterForm : public QDialog {
  Q_OBJECT
public:
  explicit MasterForm(QWidget *parent = nullptr);

  SecureString takeSecurePassword();

  // Cipher the new vault will be written with. Read it after the dialog was
  // accepted and hand it to Vault::set_cipher() before the first save. Unlike
  // the password this is not a one-shot hand-over: reading it leaves the choice
  // in place, so the caller can restore it on a retry.
  [[nodiscard]] vault::CipherAlgorithm cipher() const noexcept;

  void selectCipher(vault::CipherAlgorithm cipher);

protected:
  void showEvent(QShowEvent *event) override;
  void accept() override;
  void reject() override;

private:
  QLineEdit *passwordEdit_;
  QLineEdit *confirmEdit_;
  QComboBox *cipherBox_;
  SecureString securePassword_{""};
};