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

void Serializator::serialize(const std::string &file_path, const Vault &vault) {
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
    throw std::runtime_error("cannot serialize protobuf");

  Nonce vault_nonce = NonceManager::generate();

  std::vector<unsigned char> encrypted(serialized.size() +
                                       crypto_secretbox_MACBYTES);

  if (crypto_secretbox_easy(
          reinterpret_cast<unsigned char *>(encrypted.data()),
          reinterpret_cast<const unsigned char *>(serialized.data()),
          serialized.size(),
          reinterpret_cast<const unsigned char *>(vault_nonce.data()),
          vault.key_.data()) != 0) {
    throw std::runtime_error("vault encryption failed");
  }

  {
    std::ofstream nonce_file("vault.nonce", std::ios::binary);

    nonce_file.write(reinterpret_cast<const char *>(vault_nonce.data()),
                     vault_nonce.size());
  }

  {
    std::ofstream file(file_path, std::ios::binary);

    if (!file)
      throw std::runtime_error("cannot open file");

    file.write(reinterpret_cast<const char *>(encrypted.data()),
               encrypted.size());
  }
}

void Serializator::deserialize(const std::string &path, Vault &vault) {
  password_manager::VaultProto proto;

  std::ifstream file(path, std::ios::binary);

  if (!file)
    throw std::runtime_error("cannot open file");

  file.seekg(0, std::ios::end);
  const std::streamsize size = file.tellg();
  file.seekg(0);

  std::vector<unsigned char> encrypted(size);

  file.read(reinterpret_cast<char *>(encrypted.data()), size);

  Nonce vault_nonce = NonceManager::read_from_file("vault.nonce");

  if (encrypted.size() < crypto_secretbox_MACBYTES)
    throw std::runtime_error("corrupted vault");

  std::string decrypted(encrypted.size() - crypto_secretbox_MACBYTES, '\0');

  if (crypto_secretbox_open_easy(
          reinterpret_cast<unsigned char *>(decrypted.data()),
          reinterpret_cast<const unsigned char *>(encrypted.data()),
          encrypted.size(),
          reinterpret_cast<const unsigned char *>(vault_nonce.data()),
          vault.key_.data()) != 0) {
    throw std::runtime_error("error during decoding");
  }

  if (!proto.ParseFromString(decrypted))
    throw std::runtime_error("invalid protobuf");

  vault.entries_.clear();

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
}

void Vault::unlock(const std::string &password) {
  Salt salt = SaltManager::getSaltFromFile();
  auto key = MasterKeyManager::deriveKey(password, salt);
  if (key) {
    key_ = *key;
    std::cout << "Хранилище разблокировано" << std::endl;

  } else {
    std::cerr << "Неверный мастер-пароль" << std::endl;
  }
}

void Vault::lock(Key &key) {
  key_ = key;
  // здесь надо переписать ключ, перешифровать может быть, но это чуть позжу
}
