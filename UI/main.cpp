#include "UI.hpp"
#include <QApplication>

int main(int argc, char *argv[]) {
  if (sodium_init() < 0)
    return 1;

  vault::Vault vault;
  vault.init();
  QApplication app(argc, argv);

  QFile file(":/dark.qss");

  if (!file.open(QIODevice::ReadOnly)) {
    qDebug() << "Open failed:" << file.errorString();
    return 1;
  }

  app.setStyleSheet(QString::fromUtf8(file.readAll()));

  MainWindow window(std::move(vault));
  window.show();
  return app.exec();
}
