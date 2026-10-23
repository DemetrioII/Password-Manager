#include "UI.hpp"
#include "UI/forms/cipher_names.hpp"
#include "UI/forms/load_form.hpp"
#include "UI/forms/lock_form.hpp"
#include "UI/forms/password_form.hpp"
#include "UI/forms/secure_input.hpp"
#include "UI/forms/save_form.hpp"
#include <QStatusBar>
#include <algorithm>
#include <sodium.h>

QString describe(vault::VaultError error) {
  switch (error) {
  case vault::VaultError::WrongPassword:
    return "Wrong master password.";
  case vault::VaultError::VaultCorrupted:
    return "The vault file is corrupted.";
  case vault::VaultError::InvalidFormat:
    return "The vault file uses an unsupported or invalid format.";
  case vault::VaultError::IoError:
    return "I/O error while reading or writing the vault file.";
  case vault::VaultError::CryptoError:
    return "The cryptographic operation failed.";
  case vault::VaultError::FileOpenFailed:
    return "The vault file could not be opened.";
  case vault::VaultError::AuthenticationFailed:
    return "Authentication failed: the vault file was tampered with.";
  case vault::VaultError::SaltCorrupted:
    return "The salt in the vault header is corrupted.";
  case vault::VaultError::NonceCorrupted:
    return "The nonce in the vault header is corrupted.";
  case vault::VaultError::EntryNotFound:
    return "The entry was not found.";
  case vault::VaultError::VaultLocked:
    return "The vault is locked. Unlock it first.";
  case vault::VaultError::OutOfMemory:
    return "Out of memory during key derivation.";
  case vault::VaultError::SerializationFailed:
    return "The vault could not be serialized.";
  case vault::VaultError::EntryTooLarge:
    return "The entry exceeds the maximum allowed size.";
  case vault::VaultError::TooManyEntries:
    return "The vault already holds the maximum number of entries.";
  }
  return "Unknown error.";
}

namespace {

// Short, non-reversible tag of a clipboard payload. Used to recognise a secret
// later without keeping the secret itself in a lambda or a member variable.
// Unkeyed SipHash-2-4 is enough here: the value is only ever compared for
// equality inside this process and never leaves it.
QByteArray fingerprint(const QString &text) {
  QByteArray utf8 = text.toUtf8();
  QByteArray digest(crypto_generichash_BYTES, '\0');
  crypto_generichash(reinterpret_cast<unsigned char *>(digest.data()),
                     crypto_generichash_BYTES,
                     reinterpret_cast<const unsigned char *>(utf8.constData()),
                     static_cast<std::size_t>(utf8.size()), nullptr, 0);
  sodium_memzero(utf8.data(), static_cast<std::size_t>(utf8.size()));
  return digest;
}

} // namespace

PasswordItemWidget::PasswordItemWidget(const vault::PasswordEntry &entry,
                                       const vault::Vault &vault,
                                       const vault::UUID &ID, MainWindow *owner,
                                       bool lightweightEffects, QWidget *parent)
    : QFrame(parent), vault_(&vault), owner_(owner), id_(ID),
      lightweightEffects_(lightweightEffects) {
  setObjectName("PasswordCard");
  setFrameShape(QFrame::StyledPanel);
  setFrameShadow(QFrame::Raised);

  if (!lightweightEffects_) {
    shadowEffect_ = new QGraphicsDropShadowEffect(this);
    shadowEffect_->setBlurRadius(12);
    shadowEffect_->setOffset(0, 2);
    shadowEffect_->setColor(QColor(0, 0, 0, 40));
    setGraphicsEffect(shadowEffect_);

    hoverAnimation_ = new QPropertyAnimation(shadowEffect_, "blurRadius", this);
    hoverAnimation_->setDuration(140);
    hoverAnimation_->setEasingCurve(QEasingCurve::OutCubic);
  }

  titleLabel_ = new QLabel(QString::fromStdString(entry.title));
  titleLabel_->setStyleSheet("font-weight: 600; font-size: 11pt;");
  loginLabel_ = new QLabel(QString::fromStdString(entry.login));
  loginLabel_->setStyleSheet("color: #6b6f7a; font-size: 9pt;");

  passwordEdit_ = new QLineEdit;
  passwordEdit_->setReadOnly(true);
  passwordEdit_->setEchoMode(QLineEdit::Password);
  passwordEdit_->setInputMethodHints(
      Qt::ImhHiddenText | Qt::ImhNoAutoUppercase | Qt::ImhNoPredictiveText |
      Qt::ImhSensitiveData);
  passwordEdit_->setObjectName("PasswordField");

  showButton_ = new QToolButton;
  showButton_->setText("👁");
  showButton_->setCheckable(true);
  showButton_->setObjectName("eye");

  copyButton_ = new QToolButton;
  copyButton_->setText("📋");
  copyButton_->setObjectName("copy");

  auto *layout = new QVBoxLayout(this);
  layout->setContentsMargins(12, 10, 12, 10);
  layout->setSpacing(6);

  auto *topLayout = new QHBoxLayout;
  topLayout->addWidget(titleLabel_);
  topLayout->addStretch();
  topLayout->addWidget(copyButton_);
  topLayout->addWidget(showButton_);

  layout->addLayout(topLayout);
  layout->addWidget(loginLabel_);
  layout->addWidget(passwordEdit_);

  QObject::connect(showButton_, &QToolButton::toggled, this, [this](bool visible) {
    if (visible) {
      auto pw = vault_->ShowPassword(id_);
      if (!pw.has_value()) {
        passwordEdit_->clear();
        showButton_->setChecked(false);
        return;
      }
      const auto view = pw->view();
      passwordEdit_->setText(QString::fromUtf8(
          view.data(), static_cast<qsizetype>(view.size())));
    } else {
      passwordEdit_->clear();
    }

    passwordEdit_->setEchoMode(visible ? QLineEdit::Normal
                                       : QLineEdit::Password);
  });

  QObject::connect(copyButton_, &QToolButton::clicked, this, [this]() {
    auto pw = vault_->ShowPassword(id_);
    if (!pw.has_value()) {
      return;
    }
    const auto view = pw->view();
    const QString secret = QString::fromUtf8(
        view.data(), static_cast<qsizetype>(view.size()));
    QApplication::clipboard()->setText(secret);
    if (owner_)
      owner_->noteClipboardCopy(secret);
  });
}

vault::UUID PasswordItemWidget::get_id() const { return id_; }

void PasswordItemWidget::hidePassword() {
  showButton_->setChecked(false);
  passwordEdit_->clear();
  passwordEdit_->setEchoMode(QLineEdit::Password);
}

void PasswordItemWidget::enterEvent(QEnterEvent *event) {
  QFrame::enterEvent(event);
  if (lightweightEffects_)
    return;
  hoverAnimation_->stop();
  hoverAnimation_->setStartValue(shadowEffect_->blurRadius());
  hoverAnimation_->setEndValue(18);
  hoverAnimation_->start();
  setStyleSheet("#PasswordCard { border: 1px solid #3a3f4b; }");
}

void PasswordItemWidget::leaveEvent(QEvent *event) {
  QFrame::leaveEvent(event);
  if (lightweightEffects_)
    return;
  hoverAnimation_->stop();
  hoverAnimation_->setStartValue(shadowEffect_->blurRadius());
  hoverAnimation_->setEndValue(12);
  hoverAnimation_->start();
  setStyleSheet("");
}

MainWindow::MainWindow(vault::Vault &&vault, QWidget *parent)
    : QMainWindow(parent), vault_(std::move(vault)) {
  setWindowTitle("Password Manager");
  resize(900, 600);

  statusBar()->showMessage("Ready");

  // The cipher of the open file is not switchable from here (changing it means
  // rewriting every entry with fresh nonces), so it is shown, not offered.
  cipherLabel_ = new QLabel;
  cipherLabel_->setObjectName("cipherLabel");
  statusBar()->addPermanentWidget(cipherLabel_);
  refreshCipherIndicator();

  auto *toolbar = addToolBar("Main");

  auto *addAction = toolbar->addAction("+");
  auto *deleteAction = toolbar->addAction("-");
  auto *editAction = toolbar->addAction("Edit");
  auto *saveAction = toolbar->addAction("Save");
  auto *loadAction = toolbar->addAction("Load");
  auto *lockAction = toolbar->addAction("Lock");

  auto *central = new QWidget;

  auto *layout = new QVBoxLayout(central);
  layout->setContentsMargins(16, 12, 16, 16);
  layout->setSpacing(10);

  search_ = new QLineEdit;
  search_->setPlaceholderText("Search by title or login...");
  search_->setObjectName("search");

  passwords_ = new QListWidget;
  passwords_->setSpacing(10);
  passwords_->setContentsMargins(2, 2, 2, 2);
  passwords_->setFrameShape(QFrame::NoFrame);
  passwords_->setResizeMode(QListView::Adjust);
  passwords_->setUniformItemSizes(false);

  layout->addWidget(search_);
  layout->addWidget(passwords_);

  setCentralWidget(central);

  QObject::connect(search_, &QLineEdit::textChanged, this,
                   &MainWindow::filterPasswordList);

  QObject::connect(addAction, &QAction::triggered, this, [this]() {
    PasswordForm form(this);

    if (form.exec() != QDialog::Accepted) {
      return;
    }

    auto title = form.getTitle().toStdString();
    auto login = form.getLogin().toStdString();
    auto password = form.takeSecurePassword();

    const auto added = vault_.Add(title, login, password);
    if (!added) {
      QMessageBox::warning(this, "Error", describe(added.error()));
      return;
    }

    refreshPasswordList();
    statusBar()->showMessage("Entry added.", 3000);
  });

  QObject::connect(deleteAction, &QAction::triggered, this, [this]() {
    auto *widget = currentWidget();
    if (!widget)
      return;

    const auto answer = QMessageBox::question(
        this, "Delete entry",
        QStringLiteral("Delete the entry \"%1\"? This cannot be undone.")
            .arg(widget->title()),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (answer != QMessageBox::Yes) {
      return;
    }

    const auto removed = vault_.Remove(widget->get_id());
    if (!removed) {
      QMessageBox::critical(this, "Error", describe(removed.error()));
      return;
    }

    refreshPasswordList();
    statusBar()->showMessage("Entry deleted.", 3000);
  });

  QObject::connect(editAction, &QAction::triggered, this, [this]() {
    auto *widget = currentWidget();
    if (!widget)
      return;

    const auto idx = widget->get_id();

    const auto entry = vault_.Find(idx);
    if (!entry.has_value()) {
      QMessageBox::warning(this, "Error", describe(entry.error()));
      return;
    }

    PasswordForm form(**entry, vault_, this);
    if (form.exec() != QDialog::Accepted) {
      return;
    }

    auto title = form.getTitle().toStdString();
    auto login = form.getLogin().toStdString();
    auto password = form.takeSecurePassword();

    const auto updated = vault_.Update(idx, title, login, password);
    if (!updated) {
      QMessageBox::critical(this, "Error", describe(updated.error()));
      return;
    }

    refreshPasswordList();
    statusBar()->showMessage("Entry updated.", 3000);
  });

  QObject::connect(saveAction, &QAction::triggered, this, [this]() {
    SaveForm form(this);

    if (form.exec() == QDialog::Accepted) {
      std::string name = form.getName().toStdString();
      SecureString password = toSecureString(form.getPassword());
      form.clearSensitiveFields();

      const auto saved = vault::service::save(std::move(password), name, vault_);
      if (!saved) {
        QMessageBox::critical(this, "Error", describe(saved.error()));
        return;
      }

      vaultPath_ = name;
      QMessageBox::information(this, "Success", "Successfully serialized!");
    }
  });

  QObject::connect(loadAction, &QAction::triggered, this, [this]() {
    LoadForm form(this);
    if (form.exec() != QDialog::Accepted) {
      return;
    }

    std::string name = form.getName().toStdString();
    SecureString password = toSecureString(form.getPassword());
    form.clearSensitiveFields();

    const auto loaded = vault::service::load(std::move(password), name, vault_);
    if (!loaded) {
      QMessageBox::critical(this, "Error", describe(loaded.error()));
      return;
    }

    vaultPath_ = name;
    locked_ = false;
    clearClipboardIfOwned();
    // deserialize() took the cipher from the file we just opened.
    refreshCipherIndicator();
    refreshPasswordList();
    QMessageBox::information(this, "Success", "Deserialization was successful");
  });

  QObject::connect(lockAction, &QAction::triggered, this, [this]() {
    lock();
    // Nothing else is on screen while the vault is locked, so cancelling the
    // unlock prompt has to end the session explicitly.
    if (!requestUnlock())
      QApplication::quit();
  });

  // Populate the list immediately so a vault with entries is not shown empty
  // until the first user action.
  refreshPasswordList();
}

PasswordItemWidget *MainWindow::currentWidget() const {
  auto *item = passwords_->currentItem();
  if (!item)
    return nullptr;
  return qobject_cast<PasswordItemWidget *>(passwords_->itemWidget(item));
}

void MainWindow::refreshPasswordList() {
  passwords_->clear();

  const auto &entries = vault_.Entries();
  const bool lightweightEffects =
      entries.size() > static_cast<std::size_t>(kHeavyEffectsEntryLimit);

  for (const auto &entry : entries) {
    auto *item = new QListWidgetItem(passwords_);
    auto *widget =
        new PasswordItemWidget(entry, vault_, entry.id, this, lightweightEffects);

    const QString searchable = QString::fromStdString(entry.title) + "\n" +
                               QString::fromStdString(entry.login);
    item->setData(Qt::UserRole + 1, searchable);
    item->setSizeHint(widget->sizeHint());

    passwords_->setItemWidget(item, widget);
  }
  filterPasswordList(search_->text());
}

void MainWindow::filterPasswordList(const QString &needle) {
  const QString n = needle.trimmed();
  for (int i = 0; i < passwords_->count(); ++i) {
    auto *item = passwords_->item(i);
    if (!item) {
      continue;
    }
    const QString s = item->data(Qt::UserRole + 1).toString();
    const bool hide = !n.isEmpty() && !s.contains(n, Qt::CaseInsensitive);
    item->setHidden(hide);
  }
}

bool MainWindow::isLocked() const { return locked_; }

bool MainWindow::unlock(SecureString &&password) {
  // With a known backing file, reload metadata from disk after verifying the
  // password. Otherwise fall back to the fast in-memory unlock.
  const bool unlocked =
      vaultPath_.empty()
          ? vault_.Unlock(std::move(password))
          : vault_.UnlockAndReload(std::move(password)).has_value();

  if (!unlocked)
    return false;

  locked_ = false;
  // A reload-based unlock re-reads the header, so the cipher is re-checked here
  // too instead of trusting the value from the construction time.
  refreshCipherIndicator();
  refreshPasswordList();
  return true;
}

void MainWindow::refreshCipherIndicator() {
  cipherLabel_->setText(
      tr("Cipher: %1").arg(cipherDisplayName(vault_.cipher())));
}

void MainWindow::lock() {
  clearClipboardIfOwned();

  for (int i = 0; i < passwords_->count(); ++i) {
    auto *item = passwords_->item(i);
    if (!item)
      continue;
    if (auto *widget =
            qobject_cast<PasswordItemWidget *>(passwords_->itemWidget(item)))
      widget->hidePassword();
  }

  vault_.Lock();
  locked_ = true;
  // Lock() wipes the entry metadata, so the list is rebuilt empty instead of
  // leaving stale titles and logins on screen.
  search_->clear();
  refreshPasswordList();
  hide();
}

bool MainWindow::requestUnlock() {
  LockForm form(this);

  while (true) {
    form.setError(QString{});
    if (form.exec() != QDialog::Accepted)
      return false;

    auto password = form.takeSecurePassword();
    if (!unlock(std::move(password))) {
      form.setError(tr("Wrong master password."));
      continue;
    }

    show();
    raise();
    activateWindow();
    statusBar()->showMessage("Vault unlocked.", 3000);
    return true;
  }
}

void MainWindow::setVaultPath(std::string path) { vaultPath_ = std::move(path); }

void MainWindow::noteClipboardCopy(const QString &secret) {
  clipboardFingerprint_ = fingerprint(secret);

  // Context is the window, not the card: refreshPasswordList() deletes the
  // card (and any timer bound to it) while the secret is still on screen.
  QTimer::singleShot(kClipboardClearDelayMs, this,
                     [this]() { clearClipboardIfOwned(); });

  statusBar()->showMessage(
      tr("Password copied. The clipboard will be cleared in %1 seconds.")
          .arg(kClipboardClearDelayMs / 1000),
      5000);
}

void MainWindow::clearClipboardIfOwned() {
  if (clipboardFingerprint_.isEmpty())
    return;

  QClipboard *clipboard = QApplication::clipboard();
  if (fingerprint(clipboard->text()) == clipboardFingerprint_)
    clipboard->clear();

  std::fill(clipboardFingerprint_.begin(), clipboardFingerprint_.end(), '\0');
  clipboardFingerprint_.clear();
}

MainWindow::~MainWindow() { clearClipboardIfOwned(); }