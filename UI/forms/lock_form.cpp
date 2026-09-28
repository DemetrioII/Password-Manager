#include "UI/forms/lock_form.hpp"
#include <QDialogButtonBox>
#include <QFormLayout>

LockForm::LockForm(QWidget *parent) : QDialog(parent) {
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
