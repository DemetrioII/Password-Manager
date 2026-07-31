#include "UI.hpp"

PasswordForm::PasswordForm(QWidget *parent) {
  setWindowTitle("Please fill the form of your new password");
  resize(500, 300);

  auto *central = new QWidget;
  auto *layout = new QVBoxLayout(central);

  titleEdit = new QLineEdit;
  passwordEdit = new QLineEdit;
  loginEdit = new QLineEdit;

  layout->addWidget(titleEdit);
  layout->addWidget(loginEdit);
  layout->addWidget(passwordEdit);

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
      QString password = form.getPassword();
      passwords_->addItem(title + ": login='" + login + "', password='" +
                          password + "'");
    }
  });

  QObject::connect(saveAction, &QAction::triggered, this, [&]() {
    SaveForm form(this);

    if (form.exec() == QDialog::Accepted) {
      std::string name = form.getName().toStdString();
      SecureString password{form.getPassword().toStdString()};

      vault_.save_metadata(name);
      auto meta_salt =
          *SaltManager::getSaltFromFile("vault." + name_ + ".meta.salt.bin");
      auto master_salt =
          *SaltManager::getSaltFromFile("vault." + name_ + ".master.salt.bin");
      if (!vault::Serializator::deserialize(
               vault::derive_keys_from_password(password, meta_salt,
                                                master_salt),
               name_, vault)
               .has_value()) {
        qDebug() << "Sorry, wrong password!";
        return;
      }
      vault_.load_metadata("vault." + name_ + ".meta.salt.bin",
                           "vault." + name_ + ".master.salt.bin",
                           "vault." + name_ + ".nonce");
      if (vault::Serializator::serialize(vault::derive_keys_from_password(
                                             password, meta_salt, master_salt),
                                         name, vault)
              .has_value()) {
        qDebug() << "Successfully serialized!\n";
      } else {
        qDebug() << "Sorry, serialization failed!\n";
      }
    }
  });

  QObject::connect(loadAction, &QAction::triggered, this, [&]() {
    LoadForm form(this);
    if (form.exec() == QDialog::Accepted) {
      std::string name = form.getName().toStdString();
      SecureString password{form.getPassword().toStdString()};

      auto meta_salt =
          *SaltManager::getSaltFromFile("vault." + name + ".meta.salt.bin");
      auto master_salt =
          *SaltManager::getSaltFromFile("vault." + name + ".master.salt.bin");

      if (vault::Serializator::deserialize(
              vault::derive_keys_from_password(password, meta_salt,
                                               master_salt),
              name, vault)
              .has_value()) {
        qDebug() << "Successfully deserialized!\n";
      } else {
        qDebug() << "Sorry, deserialization failed!\n";
      }
    }
  });
}

MainWindow::~MainWindow() = default;
