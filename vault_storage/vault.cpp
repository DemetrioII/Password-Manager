#include "vault.h"
#include <fcntl.h>
#include <fstream>
#include <string>
#include <string_view>
#include <unistd.h>

std::string vault::vaultNonceFile(const std::string &name) {
  return "vault." + name + ".nonce";
}

std::pair<std::string, std::string>
vault::vaultSaltFiles(const std::string &name) {
  return std::make_pair("vault." + name + ".meta.salt.bin",
                        "vault." + name + ".master.salt.bin");
}

VaultKeys vault::derive_keys_from_password(
    const SecureString &password,
    const std::array<std::byte, crypto_pwhash_SALTBYTES> &salt_meta,
    const std::array<std::byte, crypto_pwhash_SALTBYTES> &salt_pass) {
  VaultKeys keys;

  if (crypto_pwhash(keys.meta_key.data(), keys.meta_key.size(), password.data(),
                    password.size(),
                    reinterpret_cast<const unsigned char *>(salt_meta.data()),
                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_ARGON2ID13) != 0) {
    throw std::runtime_error("Out of memory during Argon2id");
  }

  if (crypto_pwhash(keys.master_key.data(), keys.master_key.size(),
                    password.data(), password.size(),
                    reinterpret_cast<const unsigned char *>(salt_pass.data()),
                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_ARGON2ID13) != 0) {
    throw std::runtime_error("Out of memory during Argon2id");
  }

  return keys;
}

void vault::Vault::init() {
  master_salt_ = SaltManager::generateSalt();
  meta_salt_ = SaltManager::generateSalt();
  nonce_ = NonceManager::generate();
}

void vault::Vault::load_metadata(const std::string &salt_meta_file,
                                 const std::string &salt_master_file,
                                 const std::string &nonce_file) {
  nonce_ = *NonceManager::read_from_file(nonce_file);
  meta_salt_ = *SaltManager::getSaltFromFile(salt_meta_file);
  master_salt_ = *SaltManager::getSaltFromFile(salt_master_file);
}

void vault::Vault::save_metadata(const std::string &name) {
  NonceManager::write_to_file("vault." + name + ".nonce", nonce_);
  SaltManager::saveToFile(master_salt_, "vault." + name + ".master.salt.bin");
  SaltManager::saveToFile(meta_salt_, "vault." + name + ".meta.salt.bin");
}

std::expected<void, VaultError> vault::Vault::Add(PasswordEntry &&entry) {
  if (locked_)
    return std::unexpected(VaultError::VaultLocked);
  entries_.emplace_back(std::move(entry));
  return {};
}

std::expected<void, VaultError> vault::Vault::Remove(std::size_t index) {
  if (locked_)
    return std::unexpected(VaultError::VaultLocked);
  entries_.erase(entries_.begin() + index);
  return {};
}

const std::vector<PasswordEntry> &vault::Vault::Entries() const {
  return entries_;
}

std::expected<void, VaultError>
vault::Serializator::serialize(VaultKeys &&keys, const std::string &file_path,
                               const Vault &vault) {
  password_manager::VaultProto proto;

  for (const auto &entry : vault.Entries()) {
    auto *e = proto.add_entries();

    e->set_id(entry.id);
    e->set_title(entry.title);
    e->set_login(entry.login);

    Nonce nonce = NonceManager::generate();

    auto ciphertext =
        CryptoService::cypher(entry.password, nonce, keys.master_key);

    e->set_nonce(reinterpret_cast<const char *>(nonce.data()), nonce.size());

    e->set_password(reinterpret_cast<const char *>(ciphertext.data()),
                    ciphertext.size());

    e->set_notes(entry.notes);
  }

  std::string serialized;
  if (!proto.SerializeToString(&serialized))
    return std::unexpected(VaultError::IoError);

  std::vector<unsigned char> encrypted(serialized.size() +
                                       crypto_secretbox_MACBYTES);

  if (crypto_secretbox_easy(
          reinterpret_cast<unsigned char *>(encrypted.data()),
          reinterpret_cast<const unsigned char *>(serialized.data()),
          serialized.size(),
          reinterpret_cast<const unsigned char *>(vault.nonce_.data()),
          keys.meta_key.data()) != 0) {
    return std::unexpected(VaultError::CryptoError);
  }

  auto write_res = SafeFileWriter::WriteAtomic(file_path, encrypted);
  if (!write_res) {
    return std::unexpected(VaultError::FileOpenFailed);
  }

  return {};
}

std::expected<void, VaultError>
vault::Serializator::deserialize(VaultKeys &&keys, const std::string &path,
                                 Vault &vault) {
  if (vault.locked_)
    return std::unexpected(VaultError::VaultLocked);

  password_manager::VaultProto proto;
  std::ifstream file(path, std::ios::binary);

  if (!file)
    return std::unexpected(VaultError::FileOpenFailed);

  file.seekg(0, std::ios::end);
  const std::streamsize size = file.tellg();
  file.seekg(0);

  std::vector<unsigned char> encrypted(size);
  file.read(reinterpret_cast<char *>(encrypted.data()), size);

  if (encrypted.size() < crypto_secretbox_MACBYTES)
    return std::unexpected(VaultError::VaultCorrupted);

  std::string decrypted(encrypted.size() - crypto_secretbox_MACBYTES, '\0');

  if (crypto_secretbox_open_easy(
          reinterpret_cast<unsigned char *>(decrypted.data()),
          reinterpret_cast<const unsigned char *>(encrypted.data()),
          encrypted.size(),
          reinterpret_cast<const unsigned char *>(vault.nonce_.data()),
          keys.meta_key.data()) != 0) {
    return std::unexpected(VaultError::CryptoError);
  }

  if (!proto.ParseFromString(decrypted))
    return std::unexpected(VaultError::IoError);

  // 🛡️ Временный буфер для транзакционности
  std::vector<PasswordEntry> temp_entries;
  temp_entries.reserve(proto.entries_size());

  for (const auto &e : proto.entries()) {
    // 🔍 Валидация размера Nonce перед memcpy
    if (e.nonce().size() != crypto_secretbox_NONCEBYTES) {
      return std::unexpected(VaultError::VaultCorrupted);
    }

    PasswordEntry entry;
    entry.id = e.id();
    entry.title = e.title();
    entry.login = e.login();
    entry.notes = e.notes();

    Nonce nonce;
    std::memcpy(nonce.data(), e.nonce().data(), crypto_secretbox_NONCEBYTES);

    entry.password = CryptoService::decypher(SecureString{e.password()}, nonce,
                                             keys.master_key);

    temp_entries.push_back(std::move(entry));
  }

  // ✨ Атомарное обновление контейнера только при полном успехе
  vault.entries_ = std::move(temp_entries);

  return {};
}

std::expected<void, VaultError>
vault::service::save(const SecureString &password, const std::string &name,
                     Vault &vault) {
  vault.save_metadata(name);
  auto [meta_salt_path, master_salt_path] = vaultSaltFiles(name);
  auto [meta_salt, master_salt] =
      std::make_pair(SaltManager::getSaltFromFile(meta_salt_path),
                     SaltManager::getSaltFromFile(master_salt_path));
  if (!meta_salt.has_value() || !master_salt.has_value()) {
    return std::unexpected(VaultError::SaltCorrupted);
  }
  auto nonce_file = vault::vaultNonceFile(name);

  VaultKeys keys =
      vault::derive_keys_from_password(password, *meta_salt, *master_salt);

  vault.load_metadata(meta_salt_path, master_salt_path, nonce_file);
  return vault::Serializator::serialize(std::move(keys), name, vault);
}

std::expected<void, VaultError>
vault::service::load(const SecureString &password, const std::string &name,
                     Vault &vault) {
  auto [meta_salt_path, master_salt_path] = vaultSaltFiles(name);
  auto [meta_salt, master_salt] =
      std::make_pair(SaltManager::getSaltFromFile(meta_salt_path),
                     SaltManager::getSaltFromFile(master_salt_path));

  if (!meta_salt.has_value() || !master_salt.has_value()) {
    return std::unexpected(VaultError::SaltCorrupted);
  }
  auto nonce_file = vault::vaultNonceFile(name);

  VaultKeys keys =
      vault::derive_keys_from_password(password, *meta_salt, *master_salt);

  vault.load_metadata(meta_salt_path, master_salt_path, nonce_file);
  return vault::Serializator::deserialize(std::move(keys), name, vault);
}
