#include "UI.hpp"
#include <QApplication>

int main(int argc, char *argv[]) {
  if (sodium_init() < 0)
    return 1;

  SecureString password{""};
  std::cout
      << "Enter your master password (it's will be used to session key): ";
  std::cin >> password;
  vault::Vault vault(std::move(password));
  vault.Init();
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
