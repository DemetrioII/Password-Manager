#include "vault.h"
#include <fcntl.h>
#include <fstream>
#include <string>
#include <string_view>
#include <unistd.h>

void Vault::Add(const PasswordEntry &entry) { entries_.push_back(entry); }

void Vault::Remove(std::size_t index) {
  entries_.erase(entries_.begin() + index);
}

const std::vector<PasswordEntry> &Vault::Entries() const { return entries_; }

std::expected<void, VaultError>
Serializator::serialize(const std::string &file_path, const Vault &vault,
                        const std::string &vault_nonce_file) {
  password_manager::VaultProto proto;

  for (const auto &entry : vault.Entries()) {
    auto *e = proto.add_entries();

    e->set_id(entry.id);
    e->set_title(entry.title);
    e->set_login(entry.login);

    Nonce nonce = NonceManager::generate();

    auto ciphertext = CryptoService::cypher(entry.password, nonce, vault.key_);

    e->set_nonce(reinterpret_cast<const char *>(nonce.data()), nonce.size());

    e->set_password(reinterpret_cast<const char *>(ciphertext.data()),
                    ciphertext.size());

    e->set_notes(entry.notes);
  }

  std::string serialized;
  if (!proto.SerializeToString(&serialized))
    return std::unexpected(VaultError::IoError);

  Nonce vault_nonce = NonceManager::generate();

  std::vector<unsigned char> encrypted(serialized.size() +
                                       crypto_secretbox_MACBYTES);

  if (crypto_secretbox_easy(
          reinterpret_cast<unsigned char *>(encrypted.data()),
          reinterpret_cast<const unsigned char *>(serialized.data()),
          serialized.size(),
          reinterpret_cast<const unsigned char *>(vault_nonce.data()),
          vault.key_.data()) != 0) {
    return std::unexpected(VaultError::CryptoError);
  }

  NonceManager::write_to_file(vault_nonce_file, vault_nonce);

  {
    std::ofstream file(file_path, std::ios::binary);

    if (!file)
      return std::unexpected(VaultError::FileOpenFailed);

    file.write(reinterpret_cast<const char *>(encrypted.data()),
               encrypted.size());
  }

  return {};
}

std::expected<void, VaultError>
Serializator::deserialize(const std::string &path, Vault &vault,
                          const std::string &vault_nonce_file) {
  password_manager::VaultProto proto;

  std::ifstream file(path, std::ios::binary);

  if (!file)
    return std::unexpected(VaultError::FileOpenFailed);

  file.seekg(0, std::ios::end);
  const std::streamsize size = file.tellg();
  file.seekg(0);

  std::vector<unsigned char> encrypted(size);

  file.read(reinterpret_cast<char *>(encrypted.data()), size);

  auto vault_nonce_res = NonceManager::read_from_file(vault_nonce_file);

  Nonce vault_nonce;
  if (vault_nonce_res) {
    vault_nonce = *vault_nonce_res;
  } else {
    return std::unexpected(VaultError::NonceCorrupted);
  }

  if (encrypted.size() < crypto_secretbox_MACBYTES)
    return std::unexpected(VaultError::VaultCorrupted);

  std::string decrypted(encrypted.size() - crypto_secretbox_MACBYTES, '\0');

  if (crypto_secretbox_open_easy(
          reinterpret_cast<unsigned char *>(decrypted.data()),
          reinterpret_cast<const unsigned char *>(encrypted.data()),
          encrypted.size(),
          reinterpret_cast<const unsigned char *>(vault_nonce.data()),
          vault.key_.data()) != 0) {
    return std::unexpected(VaultError::CryptoError);
  }

  if (!proto.ParseFromString(decrypted))
    return std::unexpected(VaultError::IoError);

  for (const auto &e : proto.entries()) {
    PasswordEntry entry;

    entry.id = e.id();
    entry.title = e.title();
    entry.login = e.login();
    entry.notes = e.notes();

    Nonce nonce;

    std::memcpy(nonce.data(), e.nonce().data(), crypto_secretbox_NONCEBYTES);

    entry.password = CryptoService::decypher(e.password(), nonce, vault.key_);

    vault.Add(std::move(entry));
  }

  return {};
}

std::expected<void, VaultError> Vault::unlock(const std::string &password) {
  auto salt_res = SaltManager::getSaltFromFile("salt.bin");
  Salt salt;
  if (salt_res) {
    salt = *salt_res;
  } else {
    return std::unexpected(VaultError::SaltCorrupted);
  }
  auto key = MasterKeyManager::deriveKey(password, salt);
  if (key) {
    key_ = *key;
    locked_ = false;
    std::cout << "Хранилище разблокировано" << std::endl;

  } else {
    std::cerr << "Неверный мастер-пароль" << std::endl;
  }

  return {};
}

void Vault::set_key(const Key &key) { key_ = key; }

void Vault::lock() {
  sodium_memzero(key_.data(), key_.size());
  locked_ = true;
}
