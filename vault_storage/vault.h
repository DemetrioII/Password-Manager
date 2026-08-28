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
  std::expected<void, VaultError> Add(const std::string &title,
                                      const std::string &login,
                                      const SecureString &password);
  std::expected<void, VaultError> Remove(const UUID &);

  std::expected<const PasswordEntry *, VaultError> Find(const UUID &) const;

  const std::vector<PasswordEntry> &Entries() const;

  std::expected<SecureString, VaultError> ShowPassword(const UUID &) const;

  Vault(SecureString &&password);

  void Lock();

  bool Unlock(SecureString &&);

  void Init();

  Vault(Vault &&other) noexcept = default;

private:
  std::vector<PasswordEntry> entries_;
  Salt meta_salt_;
  Salt master_salt_;
  EphemeralKey session_key_;
  bool locked_ = false;

  SecureString test_magic_plaintext{"LENIN"};
  EncryptedField test_magic_ciphertext;
};

} // namespace vault
