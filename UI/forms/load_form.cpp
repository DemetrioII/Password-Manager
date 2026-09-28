#include "UI/forms/load_form.hpp"
#include <QDialogButtonBox>
#include <QFormLayout>

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
