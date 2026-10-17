#include "UI.hpp"
#include "UI/forms/lock_form.hpp"
#include "UI/forms/master_form.hpp"
#include "UI/forms/start_form.hpp"
#include "process_hardening/process_hardening.h"
#include "vault_storage/vault_serializer.h"
#include <QApplication>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QMessageBox>
#include <QStandardPaths>
#include <exception>
#include <iostream>
#include <optional>
#include <string>

namespace {

constexpr const char *kVaultFileFilter =
    "Vault files (*.vault *.pmvault);;All files (*)";

struct PreparedVault {
  vault::Vault vault;
  std::string path;
};

// Argon2id derivation is deliberately expensive, so the wait cursor is the only
// feedback available while no window is on screen yet.
class WaitCursor {
public:
  WaitCursor() { QApplication::setOverrideCursor(Qt::WaitCursor); }
  ~WaitCursor() { QApplication::restoreOverrideCursor(); }

  WaitCursor(const WaitCursor &) = delete;
  WaitCursor &operator=(const WaitCursor &) = delete;
};

QString startDirectory() {
  const QString documents =
      QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
  return documents.isEmpty() ? QDir::homePath() : documents;
}

// Returns nothing when the user cancels the file dialog.
std::optional<std::string> pickVaultPath(bool saving) {
  const QString title = saving ? QStringLiteral("Create vault file")
                               : QStringLiteral("Open vault file");

  QString path = saving ? QFileDialog::getSaveFileName(nullptr, title,
                                                       startDirectory(),
                                                       kVaultFileFilter)
                        : QFileDialog::getOpenFileName(nullptr, title,
                                                       startDirectory(),
                                                       kVaultFileFilter);
  if (path.isEmpty())
    return std::nullopt;

  if (saving && !path.endsWith(".vault", Qt::CaseInsensitive))
    path += ".vault";

  return path.toStdString();
}

std::optional<PreparedVault> createNewVault() {
  const auto path = pickVaultPath(/*saving=*/true);
  if (!path)
    return std::nullopt;

  // Kept outside the retry loop so a failed save re-offers the cipher the user
  // picked instead of quietly reverting to the default.
  vault::CipherAlgorithm cipher = vault::CipherAlgorithm::XChaCha20Poly1305;

  while (true) {
    MasterForm form;
    form.selectCipher(cipher);

    if (form.exec() != QDialog::Accepted)
      return std::nullopt;

    cipher = form.cipher();

    // Vault() and the serializer only read the password (they bind it to
    // SecureString&& without taking ownership), so the same buffer serves both
    // the session key and the file.
    SecureString password = form.takeSecurePassword();

    const WaitCursor busy;
    vault::Vault vault(std::move(password));
    vault.Init();
    // Before the serializer ever sees the vault: the cipher picks the AEAD and
    // the nonce length that both get written into the file header.
    vault.set_cipher(cipher);

    const auto saved = vault::service::save(std::move(password), *path, vault);
    if (!saved) {
      QMessageBox::critical(nullptr, "Could not create vault",
                            describe(saved.error()));
      continue;
    }

    return PreparedVault{std::move(vault), *path};
  }
}

std::optional<PreparedVault> openExistingVault() {
  const auto path = pickVaultPath(/*saving=*/false);
  if (!path)
    return std::nullopt;

  // deserialize() refuses to touch a locked vault, so the target has to start
  // out unlocked. Its initial session key is irrelevant: a successful load
  // replaces it, and a failed one leaves the object untouched.
  std::optional<vault::Vault> target;
  {
    const WaitCursor busy;
    target.emplace(SecureString{""});
  }

  while (true) {
    LockForm form;
    form.setWindowTitle(QStringLiteral("Unlock vault"));

    if (form.exec() != QDialog::Accepted)
      return std::nullopt;

    auto password = form.takeSecurePassword();

    const WaitCursor busy;
    const auto loaded = vault::service::load(std::move(password), *path, *target);
    if (loaded)
      return PreparedVault{std::move(*target), *path};

    QMessageBox::warning(nullptr, "Could not open vault",
                         describe(loaded.error()));
  }
}

std::optional<PreparedVault> chooseVault() {
  StartForm start;

  while (true) {
    if (start.exec() != QDialog::Accepted)
      return std::nullopt;

    auto prepared =
        start.createsNewVault() ? createNewVault() : openExistingVault();
    if (prepared)
      return prepared;
  }
}

} // namespace

int main(int argc, char *argv[]) {
  try {
    hardening::apply();
  } catch (const std::exception &error) {
    std::cerr << "Fatal: process hardening failed, refusing to start: "
              << error.what() << '\n';
    return 1;
  }

  if (sodium_init() < 0) {
    std::cerr << "Fatal: libsodium initialisation failed\n";
    return 1;
  }

  // QApplication must exist before any widget: the start-up flow below is
  // entirely made of dialogs.
  QApplication app(argc, argv);

  QFile file(":/dark.qss");

  if (!file.open(QIODevice::ReadOnly)) {
    std::cerr << "Fatal: could not load the application stylesheet: "
              << file.errorString().toStdString() << '\n';
    return 1;
  }

  app.setStyleSheet(QString::fromUtf8(file.readAll()));

  auto prepared = chooseVault();
  if (!prepared)
    return 0;

  MainWindow window(std::move(prepared->vault));
  window.setVaultPath(std::move(prepared->path));
  window.show();

  return app.exec();
}