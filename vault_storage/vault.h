#pragma once
#include "crypto_service/crypto.h"
#include "vault_storage/proto/vault.pb.h"
#include "vault_storage/safe_writer.h"
#include "vault_storage/vault_model.hpp"
#include <expected>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace vault {
class Vault {
  friend class Serializator;

public:
  std::expected<void, VaultError> Add(PasswordEntry &&entry);
  std::expected<void, VaultError> Remove(const UUID &);

  std::expected<PasswordEntry *, VaultError> Find(const UUID &);

  const std::vector<PasswordEntry> &Entries() const;

  Vault() = default;

  void init();

private:
  std::vector<PasswordEntry> entries_;
  Salt meta_salt_;
  Salt master_salt_;
  bool locked_ = false;
};

} // namespace vault
