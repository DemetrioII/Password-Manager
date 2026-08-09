#include "UI.hpp"

PasswordItemWidget::PasswordItemWidget(const PasswordEntry &entry, int ID,
                                       QWidget *parent)
    : QWidget(parent), id_(ID) {
  titleLabel_ = new QLabel(QString::fromStdString(entry.title));
  loginLabel_ = new QLabel(QString::fromStdString(entry.login));

  passwordEdit_ = new QLineEdit;
  passwordEdit_->setReadOnly(true);
  passwordEdit_->setEchoMode(QLineEdit::Password);

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
                   [this, &entry](bool visible) {
                     if (visible) {
                       const auto view = entry.password.view();

                       passwordEdit_->setText(QString::fromUtf8(
                           view.data(), static_cast<qsizetype>(view.size())));
                     } else {
                       passwordEdit_->clear();
                     }

                     passwordEdit_->setEchoMode(visible ? QLineEdit::Normal
                                                        : QLineEdit::Password);
                   });
}

int PasswordItemWidget::get_id() const { return id_; }

PasswordForm::PasswordForm(QWidget *parent) : QDialog(parent) {
  setWindowTitle("Please fill the form of your new password");
  resize(500, 300);

  titleEdit = new QLineEdit;
  passwordEdit = new QLineEdit;
  loginEdit = new QLineEdit;

  passwordEdit->setEchoMode(QLineEdit::Password);

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
      QString title = form.getTitle();
      QString login = form.getLogin();
      SecureString password{form.getPassword().toStdString()};
      form.clearSensitiveFields();

      PasswordEntry entry;
      entry.title = title.toStdString();
      entry.login = login.toStdString();
      entry.password = std::move(password);

      if (!vault_.Add(std::move(entry)).has_value()) {
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

    int idx = ((PasswordItemWidget *)item)->get_id();

    if (!item) {
      return;
    }

    if (vault_.Remove(idx).has_value()) {
      refreshPasswordList();
    } else {
      QMessageBox::critical(this, "error", "Unsuccessful attempt of deletion");
    }
  });

  QObject::connect(editAction, &QAction::triggered, this, [&]() {
    auto *item = passwords_->currentItem();

    int idx = ((PasswordItemWidget *)item)->get_id();
  });

  QObject::connect(saveAction, &QAction::triggered, this, [&]() {
    SaveForm form(this);

    if (form.exec() == QDialog::Accepted) {
      std::string name = form.getName().toStdString();
      SecureString password{form.getPassword().toStdString()};
      form.clearSensitiveFields();

      if (!vault::service::save(password, name, vault_).has_value()) {
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

      if (!vault::service::load(password, name, vault_).has_value()) {
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
}

void MainWindow::refreshPasswordList() {
  passwords_->clear();

  for (const auto &entry : vault_.Entries()) {
    auto *item = new QListWidgetItem(passwords_);
    auto *widget = new PasswordItemWidget(entry, passwords_->count());

    item->setSizeHint(widget->sizeHint());

    passwords_->addItem(item);
    passwords_->setItemWidget(item, widget);
  }
}

MainWindow::~MainWindow() = default;
