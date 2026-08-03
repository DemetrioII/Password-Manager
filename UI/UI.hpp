#pragma once
#include "vault_storage/vault.h"
#include <QApplication>
#include <QLineEdit>
#include <QListWidget>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QtWidgets>

class PasswordForm : public QDialog {
  Q_OBJECT
public:
  PasswordForm(QWidget *parent = nullptr);

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
  MainWindow(vault::Vault &&vault, const std::string &name,
             QWidget *parent = nullptr);
  ~MainWindow() override;

private:
  QListWidget *passwords_;
  QLineEdit *search_;

  vault::Vault vault_;
  std::string name_;
};
