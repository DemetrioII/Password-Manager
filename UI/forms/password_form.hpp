#pragma once
#include "vault_storage/vault.h"
#include <QDialog>
#include <QLineEdit>
#include <QWidget>

class PasswordForm : public QDialog {
  Q_OBJECT
public:
  explicit PasswordForm(QWidget *parent = nullptr);

  explicit PasswordForm(const vault::PasswordEntry &entry,
                        const vault::Vault &vault, QWidget *parent);

  QString getTitle() const { return titleEdit->text(); }
  QString getLogin() const { return loginEdit->text(); }
  QString getPassword() const { return passwordEdit->text(); }

  void clearSensitiveFields() { passwordEdit->clear(); }

  ~PasswordForm() override {}

signals:
  void dataSubmitted(QString title, QString login, QString password);

private:
  QLineEdit *titleEdit;
  QLineEdit *loginEdit;
  QLineEdit *passwordEdit;
};
