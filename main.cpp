#include "crypto_service/crypto.h"
#include "master_key_generator/masterkey.h"
#include "vault_storage/vault.h"

int main() {
  Key key;
  Salt salt = SaltManager::generateSalt();
  std::string master_password;
  std::cin >> master_password;
  key = *MasterKeyManager::deriveKey(master_password, salt);
  Vault vault;
  vault.lock(key);
  PasswordEntry entry;
  entry.id = "0";
  std::cin >> entry.login >> entry.password;
  Nonce nonce = NonceManager::generate();
  entry.nonce =
      std::string(reinterpret_cast<const char *>(nonce.data()), nonce.size());
  entry.title = entry.notes = "";
  vault.Add(entry);
  Serializator serializator;
  serializator.serialize(".vault.bin", vault);
  serializator.deserialize(".vault.bin", vault);
  for (auto entry : vault.Entries()) {
    std::cout << entry.id << std::endl;
    std::cout << entry.password << std::endl;
  }
  return 0;
}
