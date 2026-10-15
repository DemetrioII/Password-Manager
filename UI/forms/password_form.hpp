#pragma once
#include "master_key_generator/securestring.h"
#include "master_key_generator/utils.h"
#include "vault_storage/vault.h"
#include <QCheckBox>
#include <QDialog>
#include <QGroupBox>
#include <QLineEdit>
#include <QSpinBox>
#include <QWidget>

// Bound for a hand-written password. The generator tops out at
// PasswordGenerator::kMaxLength; this only keeps the field from growing without
// any limit at all.
inline constexpr int kManualPasswordMaxLength = 1024;

// Add / edit dialog for a single vault entry.
//
// The pending password is mirrored into a SecureString as soon as it changes,
// so it never has to be recovered from the widget after acceptance.
class PasswordForm : public QDialog {
  Q_OBJECT
public:
  explicit PasswordForm(QWidget *parent = nullptr);

  PasswordForm(const vault::PasswordEntry &entry, const vault::Vault &vault,
               QWidget *parent);

  QString getTitle() const { return titleEdit->text(); }
  QString getLogin() const { return loginEdit->text(); }

  // Hands the pending password over and scrubs every copy of it this dialog
  // holds.
  SecureString takeSecurePassword();

  void clearSensitiveFields();

  ~PasswordForm() override = default;

protected:
  void accept() override;

private:
  void buildGeneratorPanel();
  void generatePassword();
  void syncSecureBuffer();

  QLineEdit *titleEdit{nullptr};
  QLineEdit *loginEdit{nullptr};
  QLineEdit *passwordEdit{nullptr};
  QLineEdit *confirmEdit{nullptr};

  QGroupBox *generatorBox{nullptr};
  QSpinBox *lengthSpin{nullptr};
  QCheckBox *lowercaseBox{nullptr};
  QCheckBox *uppercaseBox{nullptr};
  QCheckBox *digitsBox{nullptr};
  QCheckBox *symbolsBox{nullptr};
  QCheckBox *ambiguousBox{nullptr};

  SecureString securePassword{""};
};