#include "UI.hpp"

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

PasswordForm::PasswordForm(QWidget *parent) : QDialog(parent) {
  setWindowTitle("Please fill the form of your new password");
  resize(500, 300);

  titleEdit = new QLineEdit;
  passwordEdit = new QLineEdit;
  loginEdit = new QLineEdit;

  passwordEdit->setEchoMode(QLineEdit::Password);

  passwordEdit->setInputMethodHints(Qt::ImhHiddenText | Qt::ImhNoAutoUppercase |
                                    Qt::ImhNoPredictiveText |
                                    Qt::ImhSensitiveData);

  QFormLayout *layout = new QFormLayout;
  layout->addRow("Title:", titleEdit);
  layout->addRow("Login:", loginEdit);
  layout->addRow("Password:", passwordEdit);

  QDialogButtonBox *buttonBox =
      new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);

  QObject::connect(buttonBox, &QDialogButtonBox::accepted, this,
                   &QDialog::accept);

  QObject::connect(buttonBox, &QDialogButtonBox::rejected, this,
                   &QDialog::reject);

  layout->addRow(buttonBox);

  setLayout(layout);
}

PasswordForm::PasswordForm(const vault::PasswordEntry &entry,
                           const vault::Vault &vault, QWidget *parent)
    : QDialog(parent) {
  titleEdit = new QLineEdit;
  loginEdit = new QLineEdit;
  passwordEdit = new QLineEdit;
  passwordEdit->setEchoMode(QLineEdit::Password);

  passwordEdit->setInputMethodHints(Qt::ImhHiddenText | Qt::ImhNoAutoUppercase |
                                    Qt::ImhNoPredictiveText |
                                    Qt::ImhSensitiveData);
  titleEdit->setText(QString::fromStdString(entry.title));
  loginEdit->setText(QString::fromStdString(entry.login));

  auto pass = vault.ShowPassword(entry.id);
  auto pass_view = pass->view();
  passwordEdit->setText(QString::fromUtf8(
      pass_view.data(), static_cast<qsizetype>(pass_view.size())));

  QFormLayout *layout = new QFormLayout;
  layout->addRow("Title:", titleEdit);
  layout->addRow("Login:", loginEdit);
  layout->addRow("Password:", passwordEdit);

  QDialogButtonBox *buttonBox =
      new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);

  QObject::connect(buttonBox, &QDialogButtonBox::accepted, this,
                   &QDialog::accept);

  QObject::connect(buttonBox, &QDialogButtonBox::rejected, this,
                   &QDialog::reject);

  layout->addRow(buttonBox);
  setLayout(layout);
}

SaveForm::SaveForm(QWidget *parent) : QDialog(parent) {
  setWindowTitle("Please fill form to save your vault into the file");
  nameEdit = new QLineEdit;
  passwordEdit = new QLineEdit;

  passwordEdit->setEchoMode(QLineEdit::Password);

  passwordEdit->setInputMethodHints(Qt::ImhHiddenText | Qt::ImhNoAutoUppercase |
                                    Qt::ImhNoPredictiveText |
                                    Qt::ImhSensitiveData);
  auto *layout = new QFormLayout;

  layout->addRow("Name:", nameEdit);
  layout->addRow("Password:", passwordEdit);

  auto *buttonBox =
      new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);

  QObject::connect(buttonBox, &QDialogButtonBox::accepted, this,
                   &QDialog::accept);

  QObject::connect(buttonBox, &QDialogButtonBox::rejected, this,
                   &QDialog::reject);

  layout->addRow(buttonBox);
  setLayout(layout);
}

LoadForm::LoadForm(QWidget *parent) : QDialog(parent) {
  setWindowTitle("Please fill form to load file into your file");
  nameEdit = new QLineEdit;
  passwordEdit = new QLineEdit;

  passwordEdit->setEchoMode(QLineEdit::Password);

  passwordEdit->setInputMethodHints(Qt::ImhHiddenText | Qt::ImhNoAutoUppercase |
                                    Qt::ImhNoPredictiveText |
                                    Qt::ImhSensitiveData);

  auto *layout = new QFormLayout;

  layout->addRow("Name:", nameEdit);
  layout->addRow("Password:", passwordEdit);

  QDialogButtonBox *buttonBox =
      new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);

  QObject::connect(buttonBox, &QDialogButtonBox::accepted, this,
                   &QDialog::accept);

  QObject::connect(buttonBox, &QDialogButtonBox::rejected, this,
                   &QDialog::reject);

  layout->addRow(buttonBox);
  setLayout(layout);
}

LockForm::LockForm(QWidget *parent) {
  auto *layout = new QFormLayout;

  QDialogButtonBox *buttonBox =
      new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);

  QObject::connect(buttonBox, &QDialogButtonBox::accepted, this,
                   &QDialog::accept);

  QObject::connect(buttonBox, &QDialogButtonBox::rejected, this,
                   &QDialog::reject);

  layout->addRow(buttonBox);
  setLayout(layout);
}

MainWindow::MainWindow(vault::Vault &&vault, QWidget *parent)
    : vault_(std::move(vault)) {
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
