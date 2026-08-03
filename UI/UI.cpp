#include "UI.hpp"

PasswordForm::PasswordForm(QWidget *parent) {
  setWindowTitle("Please fill the form of your new password");
  resize(500, 300);

  auto *central = new QWidget;
  auto *layout = new QVBoxLayout(central);

  auto *titleLabel = new QLabel("Title:");
  auto *passwordLabel = new QLabel("Password:");
  auto *loginLabel = new QLabel("Login:");

  titleEdit = new QLineEdit;
  passwordEdit = new QLineEdit;
  loginEdit = new QLineEdit;

  passwordEdit->setEchoMode(QLineEdit::Password);

  auto *titleBox = new QHBoxLayout;
  auto *loginBox = new QHBoxLayout;
  auto *passwordBox = new QHBoxLayout;

  titleBox->addWidget(titleLabel);
  titleBox->addWidget(titleEdit);
  loginBox->addWidget(loginLabel);
  loginBox->addWidget(loginEdit);
  passwordBox->addWidget(passwordLabel);
  passwordBox->addWidget(passwordEdit);

  titleLabel->setBuddy(titleEdit);
  loginLabel->setBuddy(loginEdit);
  passwordLabel->setBuddy(passwordEdit);

  layout->addLayout(titleBox);
  layout->addLayout(loginBox);
  layout->addLayout(passwordBox);

  auto *buttons_layout = new QHBoxLayout;

  QPushButton *okButton = new QPushButton("OK", this);
  QPushButton *cancelButton = new QPushButton("Cancel", this);

  connect(okButton, &QPushButton::clicked, this, &QDialog::accept);
  connect(cancelButton, &QPushButton::clicked, this, &QDialog::reject);

  buttons_layout->addWidget(okButton);
  buttons_layout->addWidget(cancelButton);

  layout->addLayout(buttons_layout);

  setLayout(layout);
}

SaveForm::SaveForm(QWidget *parent) {
  setWindowTitle("Please fill form to save your vault into the file");
  nameEdit = new QLineEdit;
  passwordEdit = new QLineEdit;

  passwordEdit->setEchoMode(QLineEdit::Password);

  auto *sf_layout = new QVBoxLayout;

  sf_layout->addWidget(nameEdit);
  sf_layout->addWidget(passwordEdit);

  QPushButton *okButton = new QPushButton("OK", this);
  QPushButton *cancelButton = new QPushButton("Cancel", this);

  connect(okButton, &QPushButton::clicked, this, &QDialog::accept);
  connect(cancelButton, &QPushButton::clicked, this, &QDialog::reject);

  QHBoxLayout *buttons_layout = new QHBoxLayout;
  buttons_layout->addWidget(okButton);
  buttons_layout->addWidget(cancelButton);

  sf_layout->addLayout(buttons_layout);

  setLayout(sf_layout);
}

LoadForm::LoadForm(QWidget *parent) {
  setWindowTitle("Please fill form to load file into your file");
  nameEdit = new QLineEdit;
  passwordEdit = new QLineEdit;

  passwordEdit->setEchoMode(QLineEdit::Password);

  auto *lf_layout = new QVBoxLayout;

  lf_layout->addWidget(nameEdit);
  lf_layout->addWidget(passwordEdit);

  QPushButton *okButton = new QPushButton("OK", this);
  QPushButton *cancelButton = new QPushButton("Cancel", this);

  connect(okButton, &QPushButton::clicked, this, &QDialog::accept);
  connect(cancelButton, &QPushButton::clicked, this, &QDialog::reject);

  QHBoxLayout *buttons_layout = new QHBoxLayout;
  buttons_layout->addWidget(okButton);
  buttons_layout->addWidget(cancelButton);

  lf_layout->addLayout(buttons_layout);
  setLayout(lf_layout);
}

MainWindow::MainWindow(vault::Vault &&vault, const std::string &name,
                       QWidget *parent)
    : vault_(std::move(vault)), name_(name) {
  setWindowTitle("Password Manager");
  resize(900, 600);

  auto *toolbar = addToolBar("Main");

  auto *plusAction = toolbar->addAction("+");
  toolbar->addAction("-");
  toolbar->addAction("Lock");
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

  statusBar()->showMessage("Vault locked");

  QObject::connect(plusAction, &QAction::triggered, this, [&]() {
    PasswordForm form(this);

    if (form.exec() == QDialog::Accepted) {
      QString title = form.getTitle();
      QString login = form.getLogin();
      SecureString password{form.getPassword().toStdString()};
      form.clearSensitiveFields();

      PasswordEntry entry;
      entry.title = title.toStdString();
      entry.login = login.toStdString();

      if (!vault_.Add(std::move(entry)).has_value()) {
        qDebug() << "Sorry, vault is locked. You must unlock it first to add "
                    "new entries";
      } else {
        qDebug() << "Successfully added new entry";
        passwords_->addItem("title: " + title + ", login: " + login);
      }
    }
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
        return;
      }
    }
  });
}

MainWindow::~MainWindow() = default;
