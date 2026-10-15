#include "UI/forms/start_form.hpp"
#include <QDialogButtonBox>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

StartForm::StartForm(QWidget *parent) : QDialog(parent) {
  setWindowTitle("PassManager");
  setModal(true);

  auto *heading = new QLabel("What do you want to do?");
  heading->setObjectName("startHeading");

  auto *hint = new QLabel(
      "A vault is a single encrypted file. Create a new one, or open an "
      "existing vault file from disk.");
  hint->setObjectName("startHint");
  hint->setWordWrap(true);

  auto *createButton = new QPushButton("Create new vault");
  createButton->setObjectName("startPrimary");
  createButton->setDefault(true);

  auto *openButton = new QPushButton("Open existing vault");

  auto *buttons = new QDialogButtonBox;
  buttons->addButton(createButton, QDialogButtonBox::AcceptRole);
  buttons->addButton(openButton, QDialogButtonBox::ActionRole);

  auto *layout = new QVBoxLayout(this);
  layout->addWidget(heading);
  layout->addWidget(hint);
  layout->addWidget(buttons);
  layout->setSpacing(12);

  QObject::connect(buttons, &QDialogButtonBox::accepted, this, [this]() {
    createsNew_ = true;
    accept();
  });

  QObject::connect(openButton, &QPushButton::clicked, this, [this]() {
    createsNew_ = false;
    accept();
  });
}