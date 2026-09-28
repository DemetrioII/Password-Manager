#include "vault_storage/vault_serializer.h"

#include <unordered_set>

std::expected<void, vault::VaultError>
vault::Serializator::serialize(SecureString &&password,
                               const std::string &file_path,
                               const vault::Vault &vault) {
  if (vault.locked())
    return std::unexpected(vault::VaultError::VaultLocked);

  password_manager::VaultProto proto;
  password_manager::EncryptedEntries entries;

  std::visit(
      [&proto](const auto &meta_salt, const auto &master_salt,
               const auto &ephemeral_salt) {
        proto.set_meta_salt(
            reinterpret_cast<const unsigned char *>(meta_salt.data()),
            meta_salt.size());
        proto.set_master_salt(
            reinterpret_cast<const unsigned char *>(master_salt.data()),
            master_salt.size());
        proto.set_ephemeral_salt(
            reinterpret_cast<const unsigned char *>(ephemeral_salt.data()),
            ephemeral_salt.size());
      },
      vault.meta_salt_, vault.master_salt_, vault.ephemeral_salt_);

  vault::VaultKeys keys;
  try {
    keys = vault::derive_keys_from_password(
        std::move(password), vault.meta_salt_, vault.master_salt_);
  } catch (const KDFError &) {
    return std::unexpected(vault::VaultError::OutOfMemory);
  }

  Nonce vault_nonce = NonceManager::generate<XChaCha20Poly1305Nonce>();

  vault::VaultHeader header =
      vault::make_header(vault.meta_salt_, vault.master_salt_,
                         vault.ephemeral_salt_, vault_nonce);

  for (const auto &entry : vault.Entries()) {
    auto *e = entries.add_entries();

    e->set_id(entry.id);
    e->set_title(entry.title);
    e->set_login(entry.login);

    Nonce nonce = NonceManager::generate<XChaCha20Poly1305Nonce>();

    try {
      auto ciphertext = CryptoService::cypher(
          entry.password.decrypt(vault.session_key_), nonce, keys.master_key);
      e->set_password(reinterpret_cast<const char *>(ciphertext.data()),
                      ciphertext.size());
    } catch (const CryptoError &) {
      return std::unexpected(vault::VaultError::CryptoError);
    }

    std::visit(
        [&e](const auto &nonce_value) {
          e->set_nonce(reinterpret_cast<const char *>(nonce_value.data()),
                       nonce_value.size());
        },
        nonce);

    e->set_notes(entry.notes);
  }

  std::string serialized;
  if (!entries.SerializeToString(&serialized))
    return std::unexpected(vault::VaultError::SerializationFailed);
  std::vector<unsigned char> encrypted;

  try {
    encrypted = CryptoService::encrypt(serialized.data(), serialized.size(),
                                       header.data(), header.size(),
                                       vault_nonce, keys.meta_key);
  } catch (const CryptoError &) {
    return std::unexpected(VaultError::CryptoError);
  }

  std::visit(
      [&proto](const auto &vault_nonce_v) {
        proto.set_nonce(reinterpret_cast<const char *>(vault_nonce_v.data()),
                        vault_nonce_v.size());
      },
      vault_nonce);

  proto.set_entries(reinterpret_cast<const char *>(encrypted.data()),
                    encrypted.size());

  std::string final_serialized;

  if (!proto.SerializeToString(&final_serialized))
    return std::unexpected(vault::VaultError::SerializationFailed);

  std::vector<unsigned char> file_data(final_serialized.begin(),
                                       final_serialized.end());

  auto result = SafeFileWriter::WriteAtomic(file_path, file_data);

  if (!result)
    return std::unexpected(vault::VaultError::IoError);

  return {};
}

std::expected<void, vault::VaultError>
vault::Serializator::deserialize(SecureString &&password,
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

  if (static_cast<std::size_t>(size) > MAX_VAULT_SIZE)
    return std::unexpected(vault::VaultError::VaultCorrupted);

  std::string serialized_file(size, '\0');

  if (!file.read(serialized_file.data(), size))
    return std::unexpected(vault::VaultError::IoError);

  if (!proto.ParseFromString(serialized_file))
    return std::unexpected(vault::VaultError::VaultCorrupted);

  if (proto.meta_salt().size() != crypto_pwhash_SALTBYTES ||
      proto.master_salt().size() != crypto_pwhash_SALTBYTES ||
      proto.nonce().size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES ||
      proto.ephemeral_salt().size() != crypto_pwhash_SALTBYTES)
    return std::unexpected(vault::VaultError::VaultCorrupted);

  Nonce nonce;

  Salt master_salt, meta_salt, ephemeral_salt;
  std::visit(
      [&proto](auto &master_salt_v, auto &meta_salt_v, auto &ephemeral_salt_v,
               auto &nonce_v) {
        std::memcpy(master_salt_v.data(), proto.master_salt().data(),
                    crypto_pwhash_SALTBYTES);
        std::memcpy(meta_salt_v.data(), proto.meta_salt().data(),
                    crypto_pwhash_SALTBYTES);
        std::memcpy(ephemeral_salt_v.data(), proto.ephemeral_salt().data(),
                    crypto_pwhash_SALTBYTES);
        std::memcpy(nonce_v.data(), proto.nonce().data(),
                    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
      },
      master_salt, meta_salt, ephemeral_salt, nonce);

  vault::VaultKeys keys;
  try {
    keys = vault::derive_keys_from_password(std::move(password), meta_salt,
                                            master_salt);
  } catch (const KDFError &) {
    return std::unexpected(vault::VaultError::OutOfMemory);
  }

  const std::string &encrypted_entries = proto.entries();

  if (encrypted_entries.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES)
    return std::unexpected(vault::VaultError::VaultCorrupted);

  vault::VaultHeader header =
      vault::make_header(meta_salt, master_salt, ephemeral_salt, nonce);

  std::string decrypted;

  try {
    decrypted = CryptoService::decrypt(encrypted_entries.data(),
                                       encrypted_entries.size(), header.data(),
                                       header.size(), nonce, keys.meta_key);
  } catch (const CryptoError &) {
    return std::unexpected(VaultError::CryptoError);
  }

  if (!entries.ParseFromString(decrypted))
    return std::unexpected(vault::VaultError::VaultCorrupted);

  sodium_memzero(decrypted.data(), decrypted.size());
  decrypted.clear();

  if (entries.entries_size() > MAX_ENTRIES)
    return std::unexpected(vault::VaultError::VaultCorrupted);

  EphemeralKey new_session_key(std::move(password),
                               get<Argon2Salt>(ephemeral_salt));

  EncryptedField new_magic_ciphertext =
      EncryptedField::encrypt(vault.test_magic_plaintext, new_session_key);

  // 🛡️ Temporary buffer for transactionality: the vault is only mutated after
  // every entry has been validated, so a failed load cannot leave it in a
  // half-initialised state (e.g. old entries paired with a new session key).
  std::vector<vault::PasswordEntry> temp_entries;
  temp_entries.reserve(entries.entries_size());
  std::unordered_set<std::string> seen_ids;
  seen_ids.reserve(entries.entries_size());

  for (const auto &e : entries.entries()) {
    if (e.nonce().size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
      return std::unexpected(vault::VaultError::VaultCorrupted);

    if (e.id().empty() || !seen_ids.insert(e.id()).second)
      return std::unexpected(vault::VaultError::VaultCorrupted);

    if (e.title().size() > MAX_TITLE_SIZE ||
        e.login().size() > MAX_LOGIN_SIZE || e.notes().size() > MAX_NOTES_SIZE ||
        e.password().size() > MAX_PASSWORD_CIPHERTEXT_SIZE)
      return std::unexpected(vault::VaultError::VaultCorrupted);

    vault::PasswordEntry entry;

    entry.id = e.id();
    entry.title = e.title();
    entry.login = e.login();
    entry.notes = e.notes();

    Nonce password_nonce;

    std::visit(
        [&e](auto &password_nonce_v) {
          std::memcpy(password_nonce_v.data(), e.nonce().data(),
                      password_nonce_v.size());
        },
        password_nonce);

    try {
      SecureString plaintext = CryptoService::decypher(
          SecureString{e.password()}, password_nonce, keys.master_key);

      entry.password = EncryptedField::encrypt(plaintext, new_session_key);
    } catch (const CryptoError &) {
      return std::unexpected(vault::VaultError::CryptoError);
    }

    temp_entries.push_back(std::move(entry));
  }

  vault.session_key_ = std::move(new_session_key);
  vault.meta_salt_ = meta_salt;
  vault.master_salt_ = master_salt;
  vault.ephemeral_salt_ = ephemeral_salt;
  vault.test_magic_ciphertext = std::move(new_magic_ciphertext);
  vault.entries_ = std::move(temp_entries);

  return {};
}

std::expected<void, vault::VaultError>
vault::service::save(SecureString &&password, const std::string &name,
                     vault::Vault &vault) {
  return Serializator::serialize(std::move(password), name, vault);
}

std::expected<void, vault::VaultError>
vault::service::load(SecureString &&password, const std::string &name,
                     vault::Vault &vault) {
  return Serializator::deserialize(std::move(password), name, vault);
}
