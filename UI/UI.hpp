#pragma once
#include "vault_storage/vault.h"
#include "vault_storage/vault_serializer.h"
#include <string>
#include <QApplication>
#include <QByteArray>
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

class MainWindow;

// User facing text for every VaultError value. Never returns an empty string.
QString describe(vault::VaultError error);

// Above this entry count the per-card shadow/blur animation is skipped: a vault
// may hold MAX_ENTRIES (1000) cards and the blur effect does not scale.
inline constexpr int kHeavyEffectsEntryLimit = 50;

// How long a copied password is allowed to sit in the system clipboard.
inline constexpr int kClipboardClearDelayMs = 30000;

class PasswordItemWidget : public QFrame {
  Q_OBJECT
public:
  PasswordItemWidget(const vault::PasswordEntry &entry, const vault::Vault &vault,
                     const vault::UUID &ID, MainWindow *owner,
                     bool lightweightEffects, QWidget *parent = nullptr);

  vault::UUID get_id() const;

  QString title() const { return titleLabel_->text(); }

  // Hides a revealed password again and drops the plaintext from the field.
  void hidePassword();

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
  MainWindow *owner_;
  vault::UUID id_;
  bool lightweightEffects_;
  QGraphicsDropShadowEffect *shadowEffect_{nullptr};
  QPropertyAnimation *hoverAnimation_{nullptr};
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

  // Drops every secret from the UI and the vault, then hides the window
  // without tearing the event loop down.
  void lock();

  // Shows the unlock prompt until the password is accepted or the user gives
  // up. Returns false when the user cancelled.
  bool requestUnlock();

  void setVaultPath(std::string path);

  // AEAD this vault is (or would be) written with. The core reads it back from
  // the file header on load, so after an open it is what is actually on disk.
  [[nodiscard]] vault::CipherAlgorithm cipher() const noexcept {
    return vault_.cipher();
  }

  // Called by a card after it put a password into the clipboard. Records the
  // secret by fingerprint (never by value) and arms the auto-clear timer.
  void noteClipboardCopy(const QString &secret);

  // Clears the clipboard only while it still holds the secret we put there.
  void clearClipboardIfOwned();

private:
  PasswordItemWidget *currentWidget() const;

  // Re-reads the cipher from the vault after anything that can replace it:
  // construction, a load from disk and a reload-based unlock.
  void refreshCipherIndicator();

  QListWidget *passwords_;
  QLineEdit *search_;
  QLabel *cipherLabel_;

  bool locked_{false};
  vault::Vault vault_;

  // Path of the vault file this window is bound to, or empty until the user
  // saves or loads one. Drives the reload-based unlock after a lock.
  std::string vaultPath_;

  QByteArray clipboardFingerprint_;
};