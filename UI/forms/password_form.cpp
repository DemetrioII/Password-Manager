#include "UI/forms/password_form.hpp"
#include <QDialogButtonBox>
#include <QFormLayout>

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
