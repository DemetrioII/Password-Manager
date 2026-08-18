#pragma once
#include "vault_storage/vault.h"
#include "vault_storage/vault_serializer.h"
#include <QApplication>
#include <QLineEdit>
#include <QListWidget>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QtWidgets>

class PasswordItemWidget : public QWidget {
  Q_OBJECT
public:
  explicit PasswordItemWidget(const vault::PasswordEntry &entry,
                              const vault::Vault &vault, const vault::UUID &ID,
                              QWidget *parent = nullptr);

  vault::UUID get_id() const;

private:
  QLabel *titleLabel_;
  QLabel *loginLabel_;
  QLineEdit *passwordEdit_;
  QToolButton *showButton_;
  vault::UUID id_;
};

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

signals:
  void dataSubmitted(QString title, QString login, QString password);

private:
  QLineEdit *titleEdit;
  QLineEdit *loginEdit;
  QLineEdit *passwordEdit;
};

class SaveForm : public QDialog {
  Q_OBJECT
public:
  SaveForm(QWidget *parent = nullptr);

  QString getName() { return nameEdit->text(); }
  QString getPassword() { return passwordEdit->text(); }

  void clearSensitiveFields() { passwordEdit->clear(); }

private:
  QLineEdit *nameEdit;
  QLineEdit *passwordEdit;
};

class LoadForm : public QDialog {
  Q_OBJECT
public:
  LoadForm(QWidget *parent = nullptr);

  QString getName() { return nameEdit->text(); }
  QString getPassword() { return passwordEdit->text(); }

  void clearSensitiveFields() { passwordEdit->clear(); }

private:
  QLineEdit *nameEdit;
  QLineEdit *passwordEdit;
};

class MainWindow : public QMainWindow {
  Q_OBJECT
public:
  MainWindow(vault::Vault &&vault, QWidget *parent = nullptr);
  ~MainWindow() override;

  void refreshPasswordList();

private:
  QListWidget *passwords_;
  QLineEdit *search_;

  vault::Vault vault_;
};
