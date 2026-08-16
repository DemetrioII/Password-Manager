#include "vault_storage/vault_serializer.h"

std::expected<void, vault::VaultError> vault::Serializator::serialize(
    SecureString &&password, const EphemeralKey &session_key,
    const std::string &file_path, const vault::Vault &vault) {
  password_manager::VaultProto proto;
  password_manager::EncryptedEntries entries;

  proto.set_meta_salt(
      reinterpret_cast<const unsigned char *>(vault.meta_salt_.data()),
      vault.meta_salt_.size());

  proto.set_master_salt(
      reinterpret_cast<const unsigned char *>(vault.master_salt_.data()),
      vault.master_salt_.size());

  vault::VaultKeys keys;
  try {
    keys = vault::derive_keys_from_password(
        std::move(password), vault.meta_salt_, vault.master_salt_);
  } catch (const KDFError &) {
    return std::unexpected(vault::VaultError::OutOfMemory);
  }

  Nonce vault_nonce = NonceManager::generate();

  vault::VaultHeader header =
      vault::make_header(vault.meta_salt_, vault.master_salt_, vault_nonce);

  for (const auto &entry : vault.Entries()) {
    auto *e = entries.add_entries();

    e->set_id(entry.id);
    e->set_title(entry.title);
    e->set_login(entry.login);

    Nonce nonce = NonceManager::generate();

    try {
      auto ciphertext = CryptoService::cypher(
          entry.password.decrypt(session_key), nonce, keys.master_key);
      e->set_password(reinterpret_cast<const char *>(ciphertext.data()),
                      ciphertext.size());
    } catch (const CryptoError &) {
      return std::unexpected(vault::VaultError::CryptoError);
    }

    e->set_nonce(reinterpret_cast<const char *>(nonce.data()), nonce.size());

    e->set_notes(entry.notes);
  }

  std::string serialized;
  if (!entries.SerializeToString(&serialized))
    return std::unexpected(vault::VaultError::IoError);

  std::vector<unsigned char> encrypted(
      serialized.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);

  unsigned long long encrypted_size = 0;

  if (crypto_aead_xchacha20poly1305_ietf_encrypt(
          encrypted.data(), &encrypted_size,
          reinterpret_cast<const unsigned char *>(serialized.data()),
          serialized.size(),

          reinterpret_cast<const unsigned char *>(header.data()), header.size(),

          nullptr, reinterpret_cast<const unsigned char *>(vault_nonce.data()),
          keys.meta_key.data()) != 0) {
    return std::unexpected(vault::VaultError::CryptoError);
  }

  encrypted.resize(encrypted_size);

  proto.set_nonce(reinterpret_cast<const char *>(vault_nonce.data()),
                  vault_nonce.size());

  proto.set_entries(reinterpret_cast<const char *>(encrypted.data()),
                    encrypted.size());

  std::string final_serialized;

  if (!proto.SerializeToString(&final_serialized))
    return std::unexpected(vault::VaultError::IoError);

  std::vector<unsigned char> file_data(final_serialized.begin(),
                                       final_serialized.end());

  auto result = SafeFileWriter::WriteAtomic(file_path, file_data);

  if (!result)
    return std::unexpected(vault::VaultError::FileOpenFailed);

  return {};
}

std::expected<void, vault::VaultError>
vault::Serializator::deserialize(SecureString &&password,
                                 const EphemeralKey &session_key,
                                 const std::string &path, vault::Vault &vault) {
  if (vault.locked_)
    return std::unexpected(vault::VaultError::VaultLocked);

  password_manager::VaultProto proto;
  password_manager::EncryptedEntries entries;
  std::ifstream file(path, std::ios::binary);

  if (!file)
    return std::unexpected(vault::VaultError::FileOpenFailed);

  file.seekg(0, std::ios::end);
  const std::streamsize size = file.tellg();
  file.seekg(0);

  if (size <= 0)
    return std::unexpected(vault::VaultError::VaultCorrupted);

  std::string serialized_file(size, '\0');

  if (!file.read(serialized_file.data(), size))
    return std::unexpected(vault::VaultError::FileOpenFailed);

  if (!proto.ParseFromString(serialized_file))
    return std::unexpected(vault::VaultError::VaultCorrupted);

  if (proto.meta_salt().size() != crypto_pwhash_SALTBYTES ||
      proto.master_salt().size() != crypto_pwhash_SALTBYTES ||
      proto.nonce().size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    return std::unexpected(vault::VaultError::VaultCorrupted);

  Nonce nonce;

  Salt master_salt, meta_salt;
  std::memcpy(master_salt.data(), proto.master_salt().data(),
              crypto_pwhash_SALTBYTES);
  std::memcpy(meta_salt.data(), proto.meta_salt().data(),
              crypto_pwhash_SALTBYTES);

  std::memcpy(nonce.data(), proto.nonce().data(),
              crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

  vault::VaultKeys keys = vault::derive_keys_from_password(
      std::move(password), meta_salt, master_salt);

  const std::string &encrypted_entries = proto.entries();

  if (encrypted_entries.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES)
    return std::unexpected(vault::VaultError::VaultCorrupted);

  vault::VaultHeader header = vault::make_header(meta_salt, master_salt, nonce);

  std::string decrypted(encrypted_entries.size() -
                            crypto_aead_xchacha20poly1305_ietf_ABYTES,
                        '\0');

  unsigned long long decrypted_size = 0;

  if (crypto_aead_xchacha20poly1305_ietf_decrypt(
          reinterpret_cast<unsigned char *>(decrypted.data()), &decrypted_size,
          nullptr,
          reinterpret_cast<const unsigned char *>(encrypted_entries.data()),
          encrypted_entries.size(),

          reinterpret_cast<const unsigned char *>(header.data()), header.size(),
          reinterpret_cast<const unsigned char *>(nonce.data()),
          keys.meta_key.data()) != 0) {
    return std::unexpected(vault::VaultError::CryptoError);
  }

  decrypted.resize(decrypted_size);

  if (!entries.ParseFromString(decrypted))
    return std::unexpected(vault::VaultError::VaultCorrupted);

  sodium_memzero(decrypted.data(), decrypted.size());
  decrypted.clear();

  // 🛡️ Временный буфер для транзакционности
  std::vector<vault::PasswordEntry> temp_entries;
  temp_entries.reserve(entries.entries_size());

  for (const auto &e : entries.entries()) {
    if (e.nonce().size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
      return std::unexpected(vault::VaultError::VaultCorrupted);

    vault::PasswordEntry entry;

    entry.id = e.id();
    entry.title = e.title();
    entry.login = e.login();
    entry.notes = e.notes();

    Nonce password_nonce;

    std::memcpy(password_nonce.data(), e.nonce().data(),
                crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    try {
      SecureString plaintext = CryptoService::decypher(
          SecureString{e.password()}, password_nonce, keys.master_key);

      entry.password = EncryptedField::encrypt(plaintext.view(), session_key);
    } catch (CryptoError &) {
      return std::unexpected(vault::VaultError::CryptoError);
    }

    temp_entries.push_back(std::move(entry));
  }

  vault.entries_ = std::move(temp_entries);

  return {};
}

std::expected<void, vault::VaultError>
vault::service::save(SecureString &&password, const EphemeralKey &session_key,
                     const std::string &name, vault::Vault &vault) {
  return Serializator::serialize(std::move(password), session_key, name, vault);
}

std::expected<void, vault::VaultError>
vault::service::load(SecureString &&password, const EphemeralKey &session_key,
                     const std::string &name, vault::Vault &vault) {
  return Serializator::deserialize(std::move(password), session_key, name,
                                   vault);
}
