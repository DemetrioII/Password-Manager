#pragma once
#include "master_key_generator/securestring.h"
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QWidget>

// Argon2id accepts arbitrarily long input, but an unbounded master password
// field is a foot-gun and nothing in this application needs more.
inline constexpr int kMasterPasswordMaxLength = 1024;

// Single-field master password prompt. Owns no state beyond the typed text:
// the caller pulls the password out with takeSecurePassword() and decides
// whether it was correct.
class LockForm : public QDialog {
  Q_OBJECT
public:
  explicit LockForm(QWidget *parent = nullptr);

  SecureString takeSecurePassword();

  // Error feedback rendered inside the form, so a wrong password never needs a
  // second modal dialog.
  void setError(const QString &message);

protected:
  void showEvent(QShowEvent *event) override;
  void reject() override;

private:
  QLineEdit *passwordEdit_;
  QLabel *errorLabel_;
};