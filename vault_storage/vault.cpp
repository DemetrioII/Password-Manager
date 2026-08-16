#include "vault.h"
#include <algorithm>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <string_view>
#include <unistd.h>

void vault::Vault::init() {
  master_salt_ = SaltManager::generateSalt();
  meta_salt_ = SaltManager::generateSalt();
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

std::expected<vault::PasswordEntry *, vault::VaultError>
vault::Vault::Find(const UUID &id) {
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
