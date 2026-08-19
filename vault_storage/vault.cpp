#include "vault.h"
#include <algorithm>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <string_view>
#include <unistd.h>

void vault::Vault::Init() {
  master_salt_ = SaltManager::generateSalt<Argon2Salt>();
  meta_salt_ = SaltManager::generateSalt<Argon2Salt>();
}

vault::Vault::Vault(SecureString &&password)
    : session_key_(std::move(password)) {
  test_magic_ciphertext =
      EncryptedField::encrypt(test_magic_plaintext, session_key_);
  for (auto &i : test_magic_ciphertext.ciphertext) {
    std::cout << std::hex << i << ' ';
  }
  std::cout << std::endl;
}

std::expected<void, vault::VaultError>
vault::Vault::Add(PasswordEntry &&entry) {
  if (locked_)
    return std::unexpected(VaultError::VaultLocked);
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
  return Add(
      {.title = title,
       .login = login,
       .password = EncryptedField::encrypt(password.view(), session_key_)});
}

std::expected<SecureString, vault::VaultError>
vault::Vault::ShowPassword(const UUID &id) const {
  if (locked_)
    return std::unexpected(VaultError::VaultLocked);

  auto entry = Find(id);
  if (!entry.has_value())
    return std::unexpected(VaultError::EntryNotFound);

  auto s = (*entry)->password.decrypt(session_key_);
  return s;
}

std::expected<void, vault::VaultError> vault::Vault::Remove(const UUID &id) {
  if (locked_)
    return std::unexpected(VaultError::VaultLocked);
  auto it =
      std::find_if(entries_.begin(), entries_.end(),
                   [&](const PasswordEntry &entry) { return entry.id == id; });
  if (it == entries_.end())
    return std::unexpected(VaultError::EntryNotFound);

  entries_.erase(it);
  return {};
}

std::expected<const vault::PasswordEntry *, vault::VaultError>
vault::Vault::Find(const UUID &id) const {
  if (locked_)
    return std::unexpected(VaultError::VaultLocked);
  auto it =
      std::find_if(entries_.begin(), entries_.end(),
                   [&](const PasswordEntry &entry) { return entry.id == id; });
  if (it == entries_.end())
    return std::unexpected(VaultError::EntryNotFound);
  return &(*it);
}

const std::vector<vault::PasswordEntry> &vault::Vault::Entries() const {
  return entries_;
}

void vault::Vault::Lock() {
  if (locked_)
    return;

  session_key_.reset();
  locked_ = true;
}

bool vault::Vault::Unlock(SecureString &&password) {
  auto new_potential_session_key = EphemeralKey(std::move(password));
  try {
    if (test_magic_ciphertext.decrypt(new_potential_session_key).view() ==
        test_magic_plaintext) {
      locked_ = false;
      session_key_ = std::move(new_potential_session_key);
      return true;
    } else {
      locked_ = true;
      return false;
    }
  } catch (const AuthenticationFailed &) {
    locked_ = true;
    return false;
  }
}
