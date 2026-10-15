#pragma once
#include <QDialog>
#include <QWidget>

// First screen of the application: create a brand new vault or open one that
// already exists on disk. Cancelling it quits the application.
class StartForm : public QDialog {
  Q_OBJECT
public:
  explicit StartForm(QWidget *parent = nullptr);

  bool createsNewVault() const { return createsNew_; }

private:
  bool createsNew_{false};
};