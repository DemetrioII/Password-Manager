#include <QDialog>
#include <QLineEdit>
#include <QWidget>

class LoadForm : public QDialog {
  Q_OBJECT
public:
  LoadForm(QWidget *parent = nullptr);

  QString getName() { return nameEdit->text(); }
  QString getPassword() { return passwordEdit->text(); }

  void clearSensitiveFields() { passwordEdit->clear(); }

  ~LoadForm() override {}

private:
  QLineEdit *nameEdit;
  QLineEdit *passwordEdit;
};
