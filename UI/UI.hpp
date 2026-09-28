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

  ~PasswordItemWidget() override {}

private:
  QLabel *titleLabel_;
  QLabel *loginLabel_;
  QLineEdit *passwordEdit_;
  QToolButton *showButton_;
  vault::UUID id_;
};

class MainWindow : public QMainWindow {
  Q_OBJECT
public:
  MainWindow(vault::Vault &&vault, QWidget *parent = nullptr);
  ~MainWindow() override;

  void refreshPasswordList();

  bool isLocked() const;

  bool unlock(SecureString &&password);

private:
  QListWidget *passwords_;
  QLineEdit *search_;

  bool locked_{false};
  vault::Vault vault_;
};
