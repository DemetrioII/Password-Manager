#include "UI/UI.h"
#include "crypto_service/crypto.h"
#include "master_key_generator/masterkey.h"
#include "vault_storage/vault.h"

int main(int argc, char *argv[]) {
  if (sodium_init() < 0) {
    return 1;
  }
  std::string command;
  vault::Vault vault;
  while (std::cin >> command) {
    if (command == "add") {
      std::string login;
      std::string password{""};
      std::cout << "Enter your login: ";
      std::cin >> login;
      std::cout << "Enter your password: ";
      std::cin >> password;

      PasswordEntry entry;
      entry.login = login;
      entry.password = password;
      if (!vault.Add(entry).has_value()) {
        std::cerr << "Error!" << std::endl;
      }
    }

    else if (command == "init") {
      std::string master_password;
      std::cout << "Enter your master password: ";
      std::cin >> master_password;
      vault.init();
      vault.save_metadata("first");
      vault.unlock();
    }

    else if (command == "save") {
      std::string name;
      SecureString master_password{""};
      std::cout << "Enter file name: ";
      std::cin >> name;
      std::cout << "Enter your password: ";
      std::cin >> master_password;
      Salt master_salt =
          *SaltManager::getSaltFromFile("vault.first.master.salt.bin");
      Salt meta_salt =
          *SaltManager::getSaltFromFile("vault.first.meta.salt.bin");
      vault.load_metadata("vault.first.meta.salt.bin",
                          "vault.first.master.salt.bin", "vault.first.nonce");
      if (!vault::Serializator::serialize(
               vault::derive_keys_from_password(master_password, meta_salt,
                                                master_salt),
               name, vault)
               .has_value()) {
        std::cerr << "Error during serialization" << std::endl;
      }
    }

    else if (command == "load") {
      std::string name;
      SecureString master_password{""};
      std::cout << "Enter name of vault file: ";
      std::cin >> name;
      std::cout << "Enter master password: ";
      std::cin >> master_password;
      Salt master_salt =
          *SaltManager::getSaltFromFile("vault." + name + ".master.salt.bin");
      Salt meta_salt =
          *SaltManager::getSaltFromFile("vault." + name + ".meta.salt.bin");
      vault.load_metadata("vault." + name + ".meta.salt.bin",
                          "vault." + name + ".master.salt.bin",
                          "vault." + name + ".nonce");

      if (!vault::Serializator::deserialize(
               vault::derive_keys_from_password(master_password, meta_salt,
                                                master_salt),
               name, vault)
               .has_value()) {
        std::cerr << "Error during deserialization" << std::endl;
      }
    } else if (command == "list") {
      for (const auto &e : vault.Entries()) {
        std::cout << "login: " << e.login << ", your password: '" << e.password
                  << "'" << std::endl;
      }
    }
  }
  return 0;
}
