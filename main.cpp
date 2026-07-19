#include "crypto_service/crypto.h"
#include "master_key_generator/masterkey.h"
#include "vault_storage/vault.h"

int main() {
  Key key;
  Salt salt = SaltManager::generateSalt();
  SaltManager::saveToFile(salt, "salt.bin");
  std::string master_password;
  std::cin >> master_password;
  key = *MasterKeyManager::deriveKey(master_password, salt);
  Vault vault;
  vault.set_key(key);
  PasswordEntry entry;
  entry.id = "0";
  std::cin >> entry.login >> entry.password;
  Nonce nonce = NonceManager::generate();
  entry.nonce = nonce;
  entry.title = entry.notes = "";
  vault.Add(entry);
  Serializator::serialize("vault.bin", vault, "vault.nonce");
  Serializator::deserialize("vault.bin", vault, "vault.nonce");
  return 0;
}
