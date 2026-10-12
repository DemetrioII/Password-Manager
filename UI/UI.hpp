#pragma once
#include "vault_storage/vault.h"
#include "vault_storage/vault_serializer.h"
#include <QApplication>
#include <QClipboard>
#include <QEnterEvent>
#include <QFrame>
#include <QGraphicsDropShadowEffect>
#include <QLineEdit>
#include <QListWidget>
#include <QMainWindow>
#include <QPropertyAnimation>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>
#include <QtWidgets>

class PasswordItemWidget : public QFrame {
  Q_OBJECT
public:
  explicit PasswordItemWidget(const vault::PasswordEntry &entry,
                              const vault::Vault &vault, const vault::UUID &ID,
                              QWidget *parent = nullptr);

  vault::UUID get_id() const;

  ~PasswordItemWidget() override = default;

protected:
  void enterEvent(QEnterEvent *event) override;
  void leaveEvent(QEvent *event) override;

private:
  QLabel *titleLabel_;
  QLabel *loginLabel_;
  QLineEdit *passwordEdit_;
  QToolButton *showButton_;
  QToolButton *copyButton_;
  const vault::Vault *vault_;
  vault::UUID id_;
  QGraphicsDropShadowEffect *shadowEffect_;
  QPropertyAnimation *hoverAnimation_;
};

class MainWindow : public QMainWindow {
  Q_OBJECT
public:
  MainWindow(vault::Vault &&vault, QWidget *parent = nullptr);
  ~MainWindow() override;

  void refreshPasswordList();
  void filterPasswordList(const QString &needle);

  bool isLocked() const;

  bool unlock(SecureString &&password);

private:
  QListWidget *passwords_;
  QLineEdit *search_;

  bool locked_{false};
  vault::Vault vault_;
};
