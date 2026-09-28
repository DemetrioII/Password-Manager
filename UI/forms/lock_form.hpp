#pragma once
#include <QDialog>
#include <QLineEdit>
#include <QWidget>

class LockForm : public QDialog {
  Q_OBJECT
public:
  LockForm(QWidget *parent = nullptr);
};
