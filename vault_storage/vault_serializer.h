#pragma once
#include "vault_storage/vault.h"
#include "vault_storage/vault_model.hpp"

namespace vault {
class Serializator {
public:
  [[nodiscard]]
  static std::expected<void, vault::VaultError>
  serialize(SecureString &&, const EphemeralKey &session_key,
            const std::string &file_path, const vault::Vault &vault);
  [[nodiscard]]
  static std::expected<void, vault::VaultError>
  deserialize(SecureString &&, const EphemeralKey &session_key,
              const std::string &path, vault::Vault &vault);
};

class service {
public:
  static std::expected<void, vault::VaultError>
  save(SecureString &&, const EphemeralKey &session_key,
       const std::string &name, vault::Vault &);

  static std::expected<void, vault::VaultError>
  load(SecureString &&, const EphemeralKey &session_key,
       const std::string &name, vault::Vault &);
};
} // namespace vault
