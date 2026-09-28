#include "UI.hpp"
#include "UI/forms/load_form.hpp"
#include "UI/forms/lock_form.hpp"
#include "UI/forms/password_form.hpp"
#include "UI/forms/save_form.hpp"

PasswordItemWidget::PasswordItemWidget(const vault::PasswordEntry &entry,
                                       const vault::Vault &vault,
                                       const vault::UUID &ID, QWidget *parent)
    : QWidget(parent), id_(ID) {
  titleLabel_ = new QLabel(QString::fromStdString(entry.title));
  loginLabel_ = new QLabel(QString::fromStdString(entry.login));

  passwordEdit_ = new QLineEdit;
  passwordEdit_->setReadOnly(true);
  passwordEdit_->setEchoMode(QLineEdit::Password);
  passwordEdit_->setInputMethodHints(
      Qt::ImhHiddenText | Qt::ImhNoAutoUppercase | Qt::ImhNoPredictiveText |
      Qt::ImhSensitiveData);

  showButton_ = new QToolButton;
  showButton_->setText("👁");
  showButton_->setCheckable(true);

  auto *layout = new QVBoxLayout(this);

  auto *topLayout = new QHBoxLayout;
  topLayout->addWidget(titleLabel_);
  topLayout->addStretch();
  topLayout->addWidget(showButton_);

  layout->addLayout(topLayout);
  layout->addWidget(loginLabel_);
  layout->addWidget(passwordEdit_);

  QObject::connect(showButton_, &QToolButton::toggled, this,
                   [this, &entry, &vault](bool visible) {
                     if (visible) {
                       SecureString password = *vault.ShowPassword(entry.id);
                       const auto view = password.view();

                       passwordEdit_->setText(QString::fromUtf8(
                           view.data(), static_cast<qsizetype>(view.size())));
                     } else {
                       passwordEdit_->clear();
                     }

                     passwordEdit_->setEchoMode(visible ? QLineEdit::Normal
                                                        : QLineEdit::Password);
                   });
}

vault::UUID PasswordItemWidget::get_id() const { return id_; }

MainWindow::MainWindow(vault::Vault &&vault, QWidget *parent)
    : QMainWindow(parent), vault_(std::move(vault)) {
  setWindowTitle("Password Manager");
  resize(900, 600);

  auto *toolbar = addToolBar("Main");

  auto *addAction = toolbar->addAction("+");
  auto *deleteAction = toolbar->addAction("-");
  auto *editAction = toolbar->addAction("Edit");
  auto *saveAction = toolbar->addAction("Save");
  auto *loadAction = toolbar->addAction("Load");
  auto *lockAction = toolbar->addAction("Lock");

  auto *central = new QWidget;

  auto *layout = new QVBoxLayout(central);

  search_ = new QLineEdit;
  search_->setPlaceholderText("Search...");

  passwords_ = new QListWidget;

  layout->addWidget(search_);
  layout->addWidget(passwords_);

  setCentralWidget(central);

  QObject::connect(addAction, &QAction::triggered, this, [&]() {
    PasswordForm form(this);

    if (form.exec() == QDialog::Accepted) {
      auto title = form.getTitle().toStdString();
      auto login = form.getLogin().toStdString();
      SecureString password{form.getPassword().toStdString()};
      form.clearSensitiveFields();

      if (!vault_.Add(title, login, password).has_value()) {
        qDebug() << "Sorry, vault is locked. You must unlock it first to add "
                    "new entries";
      } else {
        qDebug() << "Successfully added new entry";
        refreshPasswordList();
      }
    }
  });

  QObject::connect(deleteAction, &QAction::triggered, this, [&]() {
    auto *item = passwords_->currentItem();

    if (!item) {
      return;
    }

    auto *widget =
        qobject_cast<PasswordItemWidget *>(passwords_->itemWidget(item));

    if (!widget)
      return;
    auto idx = widget->get_id();
    if (vault_.Remove(idx).has_value()) {
      refreshPasswordList();
    } else {
      QMessageBox::critical(this, "error", "Unsuccessful attempt of deletion");
    }
  });

  QObject::connect(editAction, &QAction::triggered, this, [&]() {
    auto *item = passwords_->currentItem();

    auto *widget =
        qobject_cast<PasswordItemWidget *>(passwords_->itemWidget(item));
    if (!widget)
      return;

    const auto idx = widget->get_id();

    qDebug() << QString::fromStdString(idx);
    auto entry_res = vault_.Find(idx);
    if (!entry_res.has_value()) {
      qDebug() << "Error getting entry";
      return;
    }
    PasswordForm form(*entry_res.value(), vault_, this);
    if (form.exec() == QDialog::Accepted) {
      SecureString password{form.getPassword().toStdString()};
      vault_.Remove(idx);
      vault_.Add(form.getTitle().toStdString(), form.getLogin().toStdString(),
                 password);
      refreshPasswordList();
      form.clearSensitiveFields();
      QMessageBox::information(this, "info", "Entry was successfully updated!");
    }
  });

  QObject::connect(saveAction, &QAction::triggered, this, [&]() {
    SaveForm form(this);

    if (form.exec() == QDialog::Accepted) {
      std::string name = form.getName().toStdString();
      SecureString password{form.getPassword().toStdString()};
      form.clearSensitiveFields();

      if (!vault::service::save(std::move(password), name, vault_)
               .has_value()) {
        QMessageBox::critical(this, "error", "Unsuccessful serialization");
        return;
      } else {
        QMessageBox::information(this, "success", "Successfully serialized!");
      }
    }
  });

  QObject::connect(loadAction, &QAction::triggered, this, [&]() {
    LoadForm form(this);
    if (form.exec() == QDialog::Accepted) {
      std::string name = form.getName().toStdString();
      SecureString password{form.getPassword().toStdString()};
      form.clearSensitiveFields();

      if (!vault::service::load(std::move(password), name, vault_)
               .has_value()) {
        QMessageBox::critical(this, "error",
                              "Deserialization was unsuccessful");
        return;
      } else {
        QMessageBox::information(this, "success",
                                 "Deserialization was successful");
        refreshPasswordList();
        return;
      }
    }
  });

  QObject::connect(lockAction, &QAction::triggered, this, [&]() {
    LockForm form(this);
    if (form.exec() != QDialog::Accepted) {
      return;
    }

    vault_.Lock();
    locked_ = true;
    close();
  });
}

void MainWindow::refreshPasswordList() {
  passwords_->clear();

  for (const auto &entry : vault_.Entries()) {
    auto *item = new QListWidgetItem(passwords_);
    auto *widget = new PasswordItemWidget(entry, vault_, entry.id);

    item->setData(Qt::UserRole, passwords_->count() - 1);
    item->setSizeHint(widget->sizeHint());

    passwords_->setItemWidget(item, widget);
  }
}

bool MainWindow::isLocked() const { return locked_; }

bool MainWindow::unlock(SecureString &&password) {
  if (vault_.Unlock(std::move(password))) {
    locked_ = false;
    return true;
  }
  return false;
}

MainWindow::~MainWindow() = default;
