#pragma once
#include "crypto_service/crypto.h"
#include "vault_storage/proto/vault.pb.h"
#include <span>
#include <string>
#include <string_view>
#include <vector>

using UUID = std::string;

struct PasswordEntry {
  UUID id;
  std::string title;
  std::string login;
  std::string password;
  std::string nonce;
  std::string notes;
};

class Vault {
  friend class Serializator;

public:
  void Add(const PasswordEntry &entry);
  void Remove(std::size_t index);

  const std::vector<PasswordEntry> &Entries() const;

  void unlock(const std::string &password);

  void lock(Key &key);

  Vault() = default;

  Vault operator=(const Vault &vault);
  Vault operator=(Vault &&vault);
  Vault(const Vault &vault);
  Vault(Vault &&vault);

private:
  std::vector<PasswordEntry> entries_;
  Key key_;
};

class Serializator {
public:
  void serialize(const std::string &file_path, const Vault &vault);
  void deserialize(const std::string &path, Vault &vault);
};
