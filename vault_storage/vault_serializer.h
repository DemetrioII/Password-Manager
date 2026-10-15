#pragma once
#include "vault_storage/vault.h"
#include "vault_storage/vault_model.hpp"

namespace vault {
// Single source of truth for the on-disk vault size cap: the writer refuses to
// emit anything the loader would reject, so a saved vault is always loadable.
constexpr bool vault_file_within_limit(std::size_t size) noexcept {
  return size <= static_cast<std::size_t>(MAX_VAULT_SIZE);
}

class Serializator {
public:
  [[nodiscard]]
  static std::expected<void, vault::VaultError>
  serialize(SecureString &&, const std::string &file_path, vault::Vault &vault);
  [[nodiscard]]
  static std::expected<void, vault::VaultError>
  deserialize(SecureString &&, const std::string &path, vault::Vault &vault);
};

class service {
public:
  static std::expected<void, vault::VaultError>
  save(SecureString &&, const std::string &name, vault::Vault &);

  static std::expected<void, vault::VaultError>
  load(SecureString &&, const std::string &name, vault::Vault &);
};
} // namespace vault
