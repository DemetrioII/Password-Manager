#pragma once
#include "crypto_service/crypto.h"
#include "vault_storage/proto/vault.pb.h"
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using UUID = std::string;

enum class VaultError {
  WrongPassword,
  VaultCorrupted,
  InvalidFormat,
  IoError,
  CryptoError,
  FileOpenFailed,
  AuthenticationFailed,
};

struct PasswordEntry {
  UUID id;
  std::string title;
  std::string login;
  std::string password;
  Nonce nonce;
  std::string notes;
};

class Vault {
  friend class Serializator;

public:
  void Add(const PasswordEntry &entry);
  void Remove(std::size_t index);

  const std::vector<PasswordEntry> &Entries() const;

  void unlock(const std::string &password);

  void set_key(const Key &key);

  void lock();

  Vault() = default;

private:
  std::vector<PasswordEntry> entries_;
  Key key_;
  bool locked_;
};

class Serializator {
public:
  static std::expected<void, VaultError> serialize(const std::string &file_path,
                                                   const Vault &vault);
  static std::expected<void, VaultError> deserialize(const std::string &path,
                                                     Vault &vault);
};
