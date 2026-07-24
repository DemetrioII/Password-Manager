#include "crypto_service/crypto.h"
#include "master_key_generator/masterkey.h"
#include "vault_storage/vault.h"

int main() {
  vault::Vault vault;
  std::string login, master_password, password;
  std::cin >> master_password >> login >> password;
  PasswordEntry entry;
  entry.login = login;
  entry.password = password;
  VaultKeys keys;
  Salt master_salt = SaltManager::generateSalt();
  Salt meta_salt = SaltManager::generateSalt();
  keys.master_key = *MasterKeyManager::deriveKey(password, master_salt);
  keys.meta_key = *MasterKeyManager::deriveKey(password, meta_salt);
  Nonce vault_nonce = NonceManager::generate();
  NonceManager::write_to_file("vault.nonce", vault_nonce);
  vault.set_key(std::move(keys));
  vault.Add(entry);
  vault.unlock();
  vault::Serializator::serialize("vault.bin", vault, "vault.nonce");
  return 0;
}
