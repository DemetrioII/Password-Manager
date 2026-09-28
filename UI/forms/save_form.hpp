#pragma once
#include <QDialog>
#include <QLineEdit>
#include <QWidget>

class SaveForm : public QDialog {
  Q_OBJECT
public:
  SaveForm(QWidget *parent = nullptr);

  QString getName() { return nameEdit->text(); }
  QString getPassword() { return passwordEdit->text(); }

  void clearSensitiveFields() { passwordEdit->clear(); }

  ~SaveForm() override {}

private:
  QLineEdit *nameEdit;
  QLineEdit *passwordEdit;
};
