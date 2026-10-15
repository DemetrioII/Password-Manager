#include "vault_storage/vault_serializer.h"

#include <cstring>
#include <unordered_set>

namespace {

// Fresh nonce of the length the vault cipher requires.
Nonce generate_vault_nonce(vault::CipherAlgorithm cipher) {
  return cipher == vault::CipherAlgorithm::ChaCha20Poly1305
             ? NonceManager::generate<ChaCha20Poly1305Nonce>()
             : NonceManager::generate<XChaCha20Poly1305Nonce>();
}

password_manager::NonceAlgorithm
to_proto_nonce_algorithm(vault::CipherAlgorithm cipher) {
  return cipher == vault::CipherAlgorithm::ChaCha20Poly1305
             ? password_manager::NONCE_ALGORITHM_CHACHA20_POLY1305_IETF
             : password_manager::NONCE_ALGORITHM_XCHACHA20_POLY1305_IETF;
}

password_manager::CipherAlgorithm
to_proto_cipher_algorithm(vault::CipherAlgorithm cipher) {
  return cipher == vault::CipherAlgorithm::ChaCha20Poly1305
             ? password_manager::CIPHER_ALGORITHM_CHACHA20_POLY1305_IETF
             : password_manager::CIPHER_ALGORITHM_XCHACHA20_POLY1305_IETF;
}

// Copies nonce bytes from the file into a variant holding the alternative the
// file's cipher implies. Precondition: the byte count was validated against a
// supported nonce length and `is_xchacha` matches it.
Nonce nonce_from_bytes(const std::string &bytes, bool is_xchacha) {
  Nonce nonce;
  if (is_xchacha)
    nonce.emplace<XChaCha20Poly1305Nonce>();
  else
    nonce.emplace<ChaCha20Poly1305Nonce>();

  std::visit(
      [&bytes](auto &value) {
        std::memcpy(value.data(), bytes.data(), value.size());
      },
      nonce);
  return nonce;
}

} // namespace

std::expected<void, vault::VaultError>
vault::Serializator::serialize(SecureString &&password,
                               const std::string &file_path,
                               vault::Vault &vault) {
  if (vault.init_error_)
    return std::unexpected(*vault.init_error_);
  if (vault.locked())
    return std::unexpected(vault::VaultError::VaultLocked);

  password_manager::VaultProto proto;
  password_manager::EncryptedEntries entries;

  const vault::CipherAlgorithm cipher = vault.cipher_;

  const vault::VaultDescriptor descriptor{
      .version = vault::kVaultFormatVersion,
      .kdf_algorithm = vault::kKdfAlgorithmArgon2id13,
      .kdf_ops_limit = vault.kdf_.ops_limit,
      .kdf_mem_limit = vault.kdf_.mem_limit,
      .salt_algorithm = vault::kSaltAlgorithmArgon2,
      .nonce_algorithm = vault::nonce_algorithm_id(cipher),
      .cipher_algorithm = vault::cipher_algorithm_id(cipher),
  };

  proto.set_version(descriptor.version);
  proto.set_salt_algorithm(password_manager::SALT_ALGORITHM_ARGON2);
  proto.set_nonce_algorithm(to_proto_nonce_algorithm(cipher));
  proto.set_cipher_algorithm(to_proto_cipher_algorithm(cipher));
  proto.mutable_kdf()->set_algorithm(password_manager::KDF_ALGORITHM_ARGON2ID13);
  proto.mutable_kdf()->set_ops_limit(descriptor.kdf_ops_limit);
  proto.mutable_kdf()->set_mem_limit(descriptor.kdf_mem_limit);

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
    keys = vault::derive_keys_from_password(std::move(password), vault.meta_salt_,
                                            vault.master_salt_, vault.kdf_);
  } catch (const KDFError &) {
    return std::unexpected(vault::VaultError::OutOfMemory);
  }

  Nonce vault_nonce = generate_vault_nonce(cipher);

  vault::VaultHeader header =
      vault::make_header(vault.meta_salt_, vault.master_salt_,
                         vault.ephemeral_salt_, vault_nonce);

  const vault::VaultAad aad = vault::make_aad(descriptor, header);

  for (const auto &entry : vault.Entries()) {
    auto *e = entries.add_entries();

    e->set_id(entry.id);
    e->set_title(entry.title);
    e->set_login(entry.login);

    Nonce nonce = generate_vault_nonce(cipher);

    try {
      auto ciphertext = CryptoService::cypher(
          entry.password.decrypt(*vault.session_key_), nonce, keys.master_key);
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
                                       aad.data(), aad.size(), vault_nonce,
                                       keys.meta_key);
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

  if (!vault::vault_file_within_limit(file_data.size()))
    return std::unexpected(vault::VaultError::VaultCorrupted);

  auto result = SafeFileWriter::WriteAtomic(file_path, file_data);

  if (!result)
    return std::unexpected(vault::VaultError::IoError);

  // Remember where this vault lives so a later lock/reload can restore the
  // metadata wiped by Lock().
  vault.path_ = file_path;

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
      proto.ephemeral_salt().size() != crypto_pwhash_SALTBYTES)
    return std::unexpected(vault::VaultError::VaultCorrupted);

  // The nonce length alone selects the AEAD: 24 bytes → XChaCha20, 12 →
  // ChaCha20 (both Poly1305 IETF). Any other length cannot correspond to a
  // supported primitive.
  const bool nonce_is_xchacha =
      proto.nonce().size() == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  const bool nonce_is_chacha =
      proto.nonce().size() == crypto_aead_chacha20poly1305_ietf_NPUBBYTES;

  if (!nonce_is_xchacha && !nonce_is_chacha)
    return std::unexpected(vault::VaultError::VaultCorrupted);

  // Version gate first: anything newer than this build understands is rejected
  // before touching crypto. Absent version == legacy v0.
  const std::uint32_t version = proto.version();

  if (version > vault::kVaultFormatVersion)
    return std::unexpected(vault::VaultError::InvalidFormat);

  // v0 files were always written with the current KDF profile and authenticate
  // only the salt/nonce header; the nonce length still selects the AEAD.
  // v1/v2 files declare their profile and algorithm identifiers, which must be
  // whitelisted and mutually consistent before any derivation happens.
  KdfProfile kdf = kCurrentKdfProfile;
  vault::VaultDescriptor descriptor{};

  if (version == 1) {
    // v1 predates the cipher choice: only XChaCha20 with the original
    // algorithm ids was ever written under this version.
    if (!nonce_is_xchacha ||
        proto.kdf().algorithm() != password_manager::KDF_ALGORITHM_ARGON2ID13 ||
        proto.salt_algorithm() != password_manager::SALT_ALGORITHM_ARGON2 ||
        proto.nonce_algorithm() !=
            password_manager::NONCE_ALGORITHM_XCHACHA20_POLY1305_IETF ||
        proto.cipher_algorithm() !=
            password_manager::CIPHER_ALGORITHM_XCHACHA20_POLY1305_IETF)
      return std::unexpected(vault::VaultError::InvalidFormat);

    kdf = KdfProfile{static_cast<std::size_t>(proto.kdf().ops_limit()),
                     static_cast<std::size_t>(proto.kdf().mem_limit()),
                     kPwhashAlgorithm};

    if (!is_supported_kdf_profile(kdf))
      return std::unexpected(vault::VaultError::InvalidFormat);

    descriptor.version = version;
    descriptor.kdf_algorithm =
        static_cast<std::uint32_t>(proto.kdf().algorithm());
    descriptor.kdf_ops_limit = proto.kdf().ops_limit();
    descriptor.kdf_mem_limit = proto.kdf().mem_limit();
    descriptor.salt_algorithm =
        static_cast<std::uint32_t>(proto.salt_algorithm());
    descriptor.nonce_algorithm =
        static_cast<std::uint32_t>(proto.nonce_algorithm());
    descriptor.cipher_algorithm =
        static_cast<std::uint32_t>(proto.cipher_algorithm());
  } else if (version == 2) {
    // v2: nonce_algorithm and cipher_algorithm must agree with each other and
    // with the actual nonce length, so a file cannot claim one AEAD while
    // supplying material for another.
    const bool ids_match_nonce =
        (proto.nonce_algorithm() ==
             password_manager::NONCE_ALGORITHM_XCHACHA20_POLY1305_IETF &&
         proto.cipher_algorithm() ==
             password_manager::CIPHER_ALGORITHM_XCHACHA20_POLY1305_IETF &&
         nonce_is_xchacha) ||
        (proto.nonce_algorithm() ==
             password_manager::NONCE_ALGORITHM_CHACHA20_POLY1305_IETF &&
         proto.cipher_algorithm() ==
             password_manager::CIPHER_ALGORITHM_CHACHA20_POLY1305_IETF &&
         nonce_is_chacha);

    if (proto.kdf().algorithm() != password_manager::KDF_ALGORITHM_ARGON2ID13 ||
        proto.salt_algorithm() != password_manager::SALT_ALGORITHM_ARGON2 ||
        !ids_match_nonce)
      return std::unexpected(vault::VaultError::InvalidFormat);

    kdf = KdfProfile{static_cast<std::size_t>(proto.kdf().ops_limit()),
                     static_cast<std::size_t>(proto.kdf().mem_limit()),
                     kPwhashAlgorithm};

    if (!is_supported_kdf_profile(kdf))
      return std::unexpected(vault::VaultError::InvalidFormat);

    descriptor.version = version;
    descriptor.kdf_algorithm =
        static_cast<std::uint32_t>(proto.kdf().algorithm());
    descriptor.kdf_ops_limit = proto.kdf().ops_limit();
    descriptor.kdf_mem_limit = proto.kdf().mem_limit();
    descriptor.salt_algorithm =
        static_cast<std::uint32_t>(proto.salt_algorithm());
    descriptor.nonce_algorithm =
        static_cast<std::uint32_t>(proto.nonce_algorithm());
    descriptor.cipher_algorithm =
        static_cast<std::uint32_t>(proto.cipher_algorithm());
  }

  const Nonce nonce = nonce_from_bytes(proto.nonce(), nonce_is_xchacha);
  const vault::CipherAlgorithm cipher =
      nonce_is_xchacha ? vault::CipherAlgorithm::XChaCha20Poly1305
                       : vault::CipherAlgorithm::ChaCha20Poly1305;

  Salt master_salt, meta_salt, ephemeral_salt;
  std::visit(
      [&proto](auto &master_salt_v, auto &meta_salt_v, auto &ephemeral_salt_v) {
        std::memcpy(master_salt_v.data(), proto.master_salt().data(),
                    crypto_pwhash_SALTBYTES);
        std::memcpy(meta_salt_v.data(), proto.meta_salt().data(),
                    crypto_pwhash_SALTBYTES);
        std::memcpy(ephemeral_salt_v.data(), proto.ephemeral_salt().data(),
                    crypto_pwhash_SALTBYTES);
      },
      master_salt, meta_salt, ephemeral_salt);

  vault::VaultKeys keys;
  try {
    keys = vault::derive_keys_from_password(std::move(password), meta_salt,
                                            master_salt, kdf);
  } catch (const KDFError &) {
    return std::unexpected(vault::VaultError::OutOfMemory);
  }

  const std::string &encrypted_entries = proto.entries();

  if (encrypted_entries.size() < aead_tag_bytes(nonce))
    return std::unexpected(vault::VaultError::VaultCorrupted);

  vault::VaultHeader header =
      vault::make_header(meta_salt, master_salt, ephemeral_salt, nonce);

  std::string decrypted;

  try {
    if (version == 0) {
      decrypted = CryptoService::decrypt(encrypted_entries.data(),
                                         encrypted_entries.size(),
                                         header.data(), header.size(), nonce,
                                         keys.meta_key);
    } else {
      const vault::VaultAad aad = vault::make_aad(descriptor, header);
      decrypted = CryptoService::decrypt(encrypted_entries.data(),
                                         encrypted_entries.size(), aad.data(),
                                         aad.size(), nonce, keys.meta_key);
    }
  } catch (const CryptoError &) {
    return std::unexpected(VaultError::CryptoError);
  }

  if (!entries.ParseFromString(decrypted))
    return std::unexpected(vault::VaultError::VaultCorrupted);

  sodium_memzero(decrypted.data(), decrypted.size());
  decrypted.clear();

  if (entries.entries_size() > MAX_ENTRIES)
    return std::unexpected(vault::VaultError::VaultCorrupted);

  std::optional<EphemeralKey> new_session_key;
  try {
    new_session_key.emplace(std::move(password),
                            get<Argon2Salt>(ephemeral_salt), kdf);
  } catch (const std::exception &) {
    return std::unexpected(vault::VaultError::OutOfMemory);
  }

  EncryptedField new_magic_ciphertext =
      EncryptedField::encrypt(vault.test_magic_plaintext, *new_session_key);

  // 🛡️ Temporary buffer for transactionality: the vault is only mutated after
  // every entry has been validated, so a failed load cannot leave it in a
  // half-initialised state (e.g. old entries paired with a new session key).
  std::vector<vault::PasswordEntry> temp_entries;
  temp_entries.reserve(entries.entries_size());
  std::unordered_set<std::string> seen_ids;
  seen_ids.reserve(entries.entries_size());

  for (const auto &e : entries.entries()) {
    // Per-entry nonces must match the vault cipher: a mismatch would only fail
    // later at authentication, but rejecting early keeps error reporting crisp.
    if (e.nonce().size() != aead_nonce_bytes(nonce))
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

    const Nonce password_nonce = nonce_from_bytes(e.nonce(), nonce_is_xchacha);

    try {
      SecureString plaintext = CryptoService::decypher(
          SecureString{e.password()}, password_nonce, keys.master_key);

      entry.password = EncryptedField::encrypt(plaintext, *new_session_key);
    } catch (const CryptoError &) {
      return std::unexpected(vault::VaultError::CryptoError);
    }

    temp_entries.push_back(std::move(entry));
  }

  vault.session_key_ = std::move(*new_session_key);
  vault.meta_salt_ = meta_salt;
  vault.master_salt_ = master_salt;
  vault.ephemeral_salt_ = ephemeral_salt;
  vault.kdf_ = kdf;
  vault.cipher_ = cipher;
  vault.test_magic_ciphertext = std::move(new_magic_ciphertext);
  vault.entries_ = std::move(temp_entries);
  vault.path_ = path;
  vault.init_error_.reset();
  vault.locked_ = false;

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
