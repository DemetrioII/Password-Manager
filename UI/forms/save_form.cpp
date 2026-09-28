#include "UI/forms/save_form.hpp"
#include <QDialogButtonBox>
#include <QFormLayout>

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
