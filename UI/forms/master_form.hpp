#pragma once
#include "UI/forms/lock_form.hpp"
#include "master_key_generator/securestring.h"
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLineEdit>
#include <QWidget>

// Master password prompt with a mandatory confirmation field, used when a new
// vault is created. The confirmation never leaves this dialog: it is compared
// against the first field and then dropped.
class MasterForm : public QDialog {
  Q_OBJECT
public:
  explicit MasterForm(QWidget *parent = nullptr);

  SecureString takeSecurePassword();

protected:
  void showEvent(QShowEvent *event) override;
  void accept() override;
  void reject() override;

private:
  QLineEdit *passwordEdit_;
  QLineEdit *confirmEdit_;
  SecureString securePassword_{""};
};