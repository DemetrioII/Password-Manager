#include "UI.hpp"
#include <QApplication>

int main(int argc, char *argv[]) {
  if (sodium_init() < 0)
    return 1;

  SecureString master_password{""};
  std::string name;
  std::cout << "Enter name: ";
  std::cin >> name;
  std::cout << "Enter password: ";
  std::cin >> master_password;
  vault::Vault vault;
  vault.init();
  vault.save_metadata(name);
  vault.unlock();

  Salt meta_salt =
      *SaltManager::getSaltFromFile("vault." + name + ".meta.salt.bin");
  Salt master_salt =
      *SaltManager::getSaltFromFile("vault." + name + ".master.salt.bin");
  vault.load_metadata("vault." + name + ".meta.salt.bin",
                      "vault." + name + ".master.salt.bin",
                      "vault." + name + ".nonce");

  vault::Serializator::serialize(
      vault::derive_keys_from_password(master_password, meta_salt, master_salt),
      name, vault);
  QApplication app(argc, argv);
  MainWindow window(std::move(vault), name);
  window.show();
  return app.exec();
}
