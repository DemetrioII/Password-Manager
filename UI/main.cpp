#include "UI.hpp"
#include <QApplication>

vault::Vault create_the_vault() {
  SecureString password{""};
  std::cout
      << "Enter your master password (it's will be used to session key): ";
  std::cin >> password;
  vault::Vault vault(std::move(password));
  vault.Init();
  return vault;
}

int main(int argc, char *argv[]) {
  if (sodium_init() < 0)
    return 1;

  auto vault{create_the_vault()};
  QApplication app(argc, argv);

  QFile file(":/dark.qss");

  if (!file.open(QIODevice::ReadOnly)) {
    qDebug() << "Open failed:" << file.errorString();
    return 1;
  }

  app.setStyleSheet(QString::fromUtf8(file.readAll()));

  MainWindow window(std::move(vault));
  window.show();

  int result = app.exec();

  while (window.isLocked()) {
    SecureString pass{""};
    std::cout << "Please enter your session password: ";
    std::cin >> pass;
    if (window.unlock(std::move(pass))) {
      window.show();
      result = app.exec();
    } else {
      std::cout << "Sorry, wrong password";
      break;
    }
  }

  return result;
}
