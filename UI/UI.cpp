#include "UI.hpp"
#include "UI/forms/load_form.hpp"
#include "UI/forms/lock_form.hpp"
#include "UI/forms/password_form.hpp"
#include "UI/forms/save_form.hpp"

PasswordItemWidget::PasswordItemWidget(const vault::PasswordEntry &entry,
                                       const vault::Vault &vault,
                                       const vault::UUID &ID, QWidget *parent)
    : QFrame(parent), vault_(&vault), id_(ID) {
  setObjectName("PasswordCard");
  setFrameShape(QFrame::StyledPanel);
  setFrameShadow(QFrame::Raised);

  shadowEffect_ = new QGraphicsDropShadowEffect(this);
  shadowEffect_->setBlurRadius(12);
  shadowEffect_->setOffset(0, 2);
  shadowEffect_->setColor(QColor(0, 0, 0, 40));
  setGraphicsEffect(shadowEffect_);

  hoverAnimation_ = new QPropertyAnimation(shadowEffect_, "blurRadius", this);
  hoverAnimation_->setDuration(140);
  hoverAnimation_->setEasingCurve(QEasingCurve::OutCubic);

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
    const QString secret = QString::fromUtf8(view.data(),
                                             static_cast<qsizetype>(view.size()));
    QApplication::clipboard()->setText(secret);
    QTimer::singleShot(30000, this, [secret]() {
      QClipboard *cb = QApplication::clipboard();
      if (cb->text() == secret) {
        cb->clear();
      }
    });
  });
}

vault::UUID PasswordItemWidget::get_id() const { return id_; }

void PasswordItemWidget::enterEvent(QEnterEvent *event) {
  QFrame::enterEvent(event);
  hoverAnimation_->stop();
  hoverAnimation_->setStartValue(shadowEffect_->blurRadius());
  hoverAnimation_->setEndValue(18);
  hoverAnimation_->start();
  setStyleSheet("#PasswordCard { border: 1px solid #3a3f4b; }");
}

void PasswordItemWidget::leaveEvent(QEvent *event) {
  QFrame::leaveEvent(event);
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

  QObject::connect(search_, &QLineEdit::textChanged, this,
                   &MainWindow::filterPasswordList);

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
    if (!item) {
      return;
    }

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
  if (vault_.Unlock(std::move(password))) {
    locked_ = false;
    return true;
  }
  return false;
}

MainWindow::~MainWindow() = default;
