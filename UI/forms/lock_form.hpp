#pragma once
#include "master_key_generator/securestring.h"
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLineEdit>
#include <QWidget>

class LockForm : public QDialog {
  Q_OBJECT
public:
  LockForm(QWidget *parent = nullptr);

  QString getPassword() const;
  SecureString takeSecurePassword();
  void clearSensitiveFields();

private:
  QLineEdit *passwordEdit_;
};
