#include "vault.h"
#include "vault_storage/vault_serializer.h"
#include <algorithm>
#include <fcntl.h>
#include <fstream>
#include <sodium.h>
#include <string>
#include <string_view>
#include <unistd.h>

void vault::Vault::Init() {
  master_salt_ = SaltManager::generateSalt<Argon2Salt>();
  meta_salt_ = SaltManager::generateSalt<Argon2Salt>();
}

vault::Vault::Vault(SecureString &&password,
                    const UnlockThrottle::Config &throttle_config)
    : ephemeral_salt_(SaltManager::generateSalt<Argon2Salt>()),
      throttle_(throttle_config) {
  try {
    session_key_.emplace(std::move(password),
                         get<Argon2Salt>(ephemeral_salt_));
    test_magic_ciphertext =
        EncryptedField::encrypt(test_magic_plaintext, *session_key_);
  } catch (const std::exception &) {
    init_error_ = VaultError::OutOfMemory;
    session_key_.reset();
  }
}

std::expected<void, vault::VaultError>
vault::Vault::ensureUnlocked() const {
  if (init_error_)
    return std::unexpected(*init_error_);
  if (locked_)
    return std::unexpected(VaultError::VaultLocked);
  return {};
}

std::expected<void, vault::VaultError>
vault::Vault::Add(PasswordEntry &&entry) {
  if (auto ready = ensureUnlocked(); !ready)
    return std::unexpected(ready.error());
  if (entries_.size() >= MAX_ENTRIES)
    return std::unexpected(VaultError::TooManyEntries);
  if (entry.title.size() > MAX_TITLE_SIZE ||
      entry.login.size() > MAX_LOGIN_SIZE ||
      entry.notes.size() > MAX_NOTES_SIZE)
    return std::unexpected(VaultError::EntryTooLarge);
  if (entry.password.ciphertext.size() > MAX_PASSWORD_CIPHERTEXT_SIZE)
    return std::unexpected(VaultError::EntryTooLarge);
  {
    std::array<unsigned char, 16> bytes;
    randombytes_buf(bytes.data(), bytes.size());

    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    entry.id =
        std::string(reinterpret_cast<const char *>(bytes.data()), bytes.size());
  }
  entries_.emplace_back(std::move(entry));
  return {};
}

std::expected<void, vault::VaultError>
vault::Vault::Add(const std::string &title, const std::string &login,
                  const SecureString &password) {
  if (auto ready = ensureUnlocked(); !ready)
    return std::unexpected(ready.error());
  if (entries_.size() >= MAX_ENTRIES)
    return std::unexpected(VaultError::TooManyEntries);
  if (title.size() > MAX_TITLE_SIZE || login.size() > MAX_LOGIN_SIZE)
    return std::unexpected(VaultError::EntryTooLarge);
  EncryptedField ef;
  try {
    ef = EncryptedField::encrypt(password, *session_key_);
  } catch (...) {
    return std::unexpected(VaultError::CryptoError);
  }
  if (ef.ciphertext.size() > MAX_PASSWORD_CIPHERTEXT_SIZE)
    return std::unexpected(VaultError::EntryTooLarge);
  return Add({.id = {},
              .title = title,
              .login = login,
              .password = std::move(ef),
              .notes = {}});
}

std::expected<SecureString, vault::VaultError>
vault::Vault::ShowPassword(const UUID &id) const {
  if (auto ready = ensureUnlocked(); !ready)
    return std::unexpected(ready.error());

  auto entry = Find(id);
  if (!entry.has_value())
    return std::unexpected(VaultError::EntryNotFound);

  try {
    SecureString s = (*entry)->password.decrypt(*session_key_);
    return s;
  } catch (const CryptoError &) {
    return std::unexpected(VaultError::CryptoError);
  }
}

std::expected<void, vault::VaultError> vault::Vault::Remove(const UUID &id) {
  if (auto ready = ensureUnlocked(); !ready)
    return std::unexpected(ready.error());
  auto it =
      std::find_if(entries_.begin(), entries_.end(),
                   [&](const PasswordEntry &entry) { return entry.id == id; });
  if (it == entries_.end())
    return std::unexpected(VaultError::EntryNotFound);

  wipe(*it);

  entries_.erase(it);
  return {};
}

std::expected<const vault::PasswordEntry *, vault::VaultError>
vault::Vault::Find(const UUID &id) const {
  if (auto ready = ensureUnlocked(); !ready)
    return std::unexpected(ready.error());
  auto it =
      std::find_if(entries_.begin(), entries_.end(),
                   [&](const PasswordEntry &entry) { return entry.id == id; });
  if (it == entries_.end())
    return std::unexpected(VaultError::EntryNotFound);
  return &(*it);
}

const std::vector<vault::PasswordEntry> &vault::Vault::Entries() const {
  static const std::vector<PasswordEntry> locked_placeholder;
  return locked_ ? locked_placeholder : entries_;
}

void vault::Vault::Lock() {
  if (locked_)
    return;

  for (auto &entry : entries_)
    entry.wipeMetadata();

  session_key_.reset();
  locked_ = true;
}

std::expected<std::optional<EphemeralKey>, vault::VaultError>
vault::Vault::deriveAndVerify(const SecureString &password) {
  if (init_error_)
    return std::unexpected(*init_error_);

  std::optional<EphemeralKey> candidate;
  try {
    candidate.emplace(password, get<Argon2Salt>(ephemeral_salt_), kdf_);
  } catch (const std::exception &) {
    return std::unexpected(VaultError::OutOfMemory);
  }

  bool matches = false;
  try {
    matches =
        test_magic_ciphertext.decrypt(*candidate) == test_magic_plaintext;
  } catch (const CryptoError &) {
    matches = false;
  }

  if (!matches) {
    throttle_.RecordFailure();
    return std::optional<EphemeralKey>{};
  }

  throttle_.RecordSuccess();
  return std::optional<EphemeralKey>(std::move(*candidate));
}

bool vault::Vault::Unlock(SecureString &&password) {
  auto candidate = deriveAndVerify(password);
  if (!candidate || !*candidate) {
    locked_ = true;
    return false;
  }
  session_key_ = std::move(**candidate);
  locked_ = false;
  return true;
}

std::expected<void, vault::VaultError>
vault::Vault::UnlockAndReload(SecureString &&password) {
  auto candidate = deriveAndVerify(password);

  if (!candidate) {
    locked_ = true;
    session_key_.reset();
    return std::unexpected(candidate.error());
  }

  if (!*candidate) {
    locked_ = true;
    session_key_.reset();
    return std::unexpected(VaultError::WrongPassword);
  }

  // No backing file yet: we cannot recover wiped metadata, so keep the old
  // fast in-memory semantics.
  if (path_.empty()) {
    session_key_ = std::move(**candidate);
    locked_ = false;
    return {};
  }

  // deserialize() refuses to touch a locked vault, so flip the flag for the
  // transactional reload and restore it if the file cannot be read. The
  // password is only consumed here, after the fast check above.
  const bool was_locked = locked_;
  locked_ = false;
  auto result = Serializator::deserialize(std::move(password), path_, *this);
  if (!result) {
    locked_ = was_locked;
    if (was_locked)
      session_key_.reset();
    return std::unexpected(result.error());
  }
  return {};
}

std::expected<void, vault::VaultError>
vault::Vault::Update(const UUID &id, const std::string &title,
                     const std::string &login, const SecureString &password) {
  if (auto ready = ensureUnlocked(); !ready)
    return std::unexpected(ready.error());
  auto it = std::find_if(entries_.begin(), entries_.end(),
                         [&](const PasswordEntry &entry) { return entry.id == id; });
  if (it == entries_.end())
    return std::unexpected(VaultError::EntryNotFound);
  if (title.size() > MAX_TITLE_SIZE || login.size() > MAX_LOGIN_SIZE)
    return std::unexpected(VaultError::EntryTooLarge);
  EncryptedField ef;
  try {
    ef = EncryptedField::encrypt(password, *session_key_);
  } catch (const CryptoError &) {
    return std::unexpected(VaultError::CryptoError);
  }
  if (ef.ciphertext.size() > MAX_PASSWORD_CIPHERTEXT_SIZE)
    return std::unexpected(VaultError::EntryTooLarge);
  it->title = title;
  it->login = login;
  it->password = std::move(ef);
  return {};
}

std::expected<void, vault::VaultError>
vault::Vault::SetNotes(const UUID &id, const std::string &notes) {
  if (auto ready = ensureUnlocked(); !ready)
    return std::unexpected(ready.error());
  auto it = std::find_if(entries_.begin(), entries_.end(),
                         [&](const PasswordEntry &entry) { return entry.id == id; });
  if (it == entries_.end())
    return std::unexpected(VaultError::EntryNotFound);
  if (notes.size() > MAX_NOTES_SIZE)
    return std::unexpected(VaultError::EntryTooLarge);
  it->notes = notes;
  return {};
}

std::expected<void, vault::VaultError>
vault::Vault::SetPassword(SecureString &&old, SecureString &&new_pw,
                          const std::string &path) {
  if (auto ready = ensureUnlocked(); !ready)
    return std::unexpected(ready.error());
  try {
    auto candidate = EphemeralKey(old, get<Argon2Salt>(ephemeral_salt_), kdf_);
    if (test_magic_ciphertext.decrypt(candidate) != test_magic_plaintext)
      return std::unexpected(VaultError::WrongPassword);
  } catch (const CryptoError &) {
    return std::unexpected(VaultError::WrongPassword);
  } catch (const std::exception &) {
    return std::unexpected(VaultError::OutOfMemory);
  }

  const auto old_entries = entries_;
  const auto old_meta = meta_salt_;
  const auto old_master = master_salt_;
  const auto old_ephemeral = ephemeral_salt_;
  const auto old_kdf = kdf_;

  std::optional<EphemeralKey> old_session_key;
  try {
    old_session_key.emplace(old, get<Argon2Salt>(old_ephemeral), old_kdf);
  } catch (const std::exception &) {
    return std::unexpected(VaultError::OutOfMemory);
  }

  auto meta_salt_new = SaltManager::generateSalt<Argon2Salt>();
  auto master_salt_new = SaltManager::generateSalt<Argon2Salt>();
  auto ephemeral_salt_new = SaltManager::generateSalt<Argon2Salt>();
  auto kdf_new = kdf_;

  std::optional<EphemeralKey> new_session_key;
  try {
    new_session_key.emplace(new_pw, get<Argon2Salt>(ephemeral_salt_new),
                            kdf_new);
  } catch (const std::exception &) {
    return std::unexpected(VaultError::OutOfMemory);
  }

  std::vector<PasswordEntry> temp_entries;
  temp_entries.reserve(old_entries.size());
  for (const auto &e : old_entries) {
    PasswordEntry ne;
    ne.id = e.id;
    ne.title = e.title;
    ne.login = e.login;
    ne.notes = e.notes;
    try {
      SecureString plain = e.password.decrypt(*old_session_key);
      ne.password = EncryptedField::encrypt(plain, *new_session_key);
    } catch (const CryptoError &) {
      return std::unexpected(VaultError::CryptoError);
    }
    temp_entries.push_back(std::move(ne));
  }

  meta_salt_ = std::move(meta_salt_new);
  master_salt_ = std::move(master_salt_new);
  ephemeral_salt_ = std::move(ephemeral_salt_new);
  kdf_ = kdf_new;
  session_key_ = std::move(*new_session_key);
  entries_ = std::move(temp_entries);
  test_magic_ciphertext =
      EncryptedField::encrypt(test_magic_plaintext, *session_key_);

  auto res = Serializator::serialize(std::move(new_pw), path, *this);
  if (!res) {
    meta_salt_ = old_meta;
    master_salt_ = old_master;
    ephemeral_salt_ = old_ephemeral;
    kdf_ = old_kdf;
    try {
      session_key_.emplace(old, get<Argon2Salt>(old_ephemeral), old_kdf);
    } catch (const std::exception &) {
      session_key_.reset();
      init_error_ = VaultError::OutOfMemory;
      locked_ = true;
      return std::unexpected(VaultError::OutOfMemory);
    }
    entries_ = old_entries;
    test_magic_ciphertext =
        EncryptedField::encrypt(test_magic_plaintext, *session_key_);
    return std::unexpected(res.error());
  }
  return {};
}
