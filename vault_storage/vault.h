#pragma once
#include "crypto_service/crypto.h"
#include "vault_storage/proto/vault.pb.h"
#include <expected>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
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
  SaltCorrupted,
  NonceCorrupted,
  VaultLocked,
};

enum class FileIoError {
  TempFileCreationFailed,
  WriteFailed,
  SyncFailed,
  RenameFailed,
  PermissionSetFailed,
};

class SafeFileWriter {
public:
  static std::expected<void, FileIoError>
  WriteAtomic(const std::filesystem::path &target_path,
              const std::vector<unsigned char> &data) {
    std::filesystem::path temp_path = target_path;
    temp_path += ".tmp." + std::to_string(getpid());

    std::ofstream file(temp_path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
      return std::unexpected(FileIoError::TempFileCreationFailed);
    }

    std::error_code ec;
    std::filesystem::permissions(temp_path,
                                 std::filesystem::perms::owner_read |
                                     std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace, ec);

    if (ec) {
      std::filesystem::remove(temp_path, ec);
      return std::unexpected(FileIoError::PermissionSetFailed);
    }

    file.write(reinterpret_cast<const char *>(data.data()), data.size());
    if (!file.good()) {
      file.close();
      std::filesystem::remove(temp_path, ec);
      return std::unexpected(FileIoError::WriteFailed);
    }

    file.flush();

    file.close();

    int fd = ::open(temp_path.c_str(), O_WRONLY);
    if (fd != -1) {
      ::fsync(fd);
      ::close(fd);
    } else {
      std::filesystem::remove(temp_path, ec);
      return std::unexpected(FileIoError::SyncFailed);
    }

    std::filesystem::rename(temp_path, target_path, ec);
    if (ec) {
      std::filesystem::remove(temp_path, ec);
      return std::unexpected(FileIoError::RenameFailed);
    }

    sync_directory(target_path.parent_path());

    return {};
  }

private:
  static void sync_directory(const std::filesystem::path &dir_path) {
    auto path_to_open = dir_path.empty() ? "." : dir_path;
    int dir_fd = ::open(dir_path.c_str(), O_RDONLY | O_DIRECTORY);
    if (dir_fd != -1) {
      ::fsync(dir_fd);
      ::close(dir_fd);
    }
  }
};

struct PasswordEntry {
  UUID id;
  std::string title;
  std::string login;
  EncryptedField password;
  Nonce nonce;
  std::string notes;
};

struct VaultKeys {
  Key meta_key;
  Key master_key;
};

namespace vault {
using VaultHeader =
    std::array<std::byte, crypto_pwhash_SALTBYTES * 2 +
                              crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>;

VaultHeader make_header(const Salt &meta_salt, const Salt &master_salt,
                        const Nonce &nonce);

VaultKeys derive_keys_from_password(
    SecureString &&password,
    const std::array<std::byte, crypto_pwhash_SALTBYTES> &salt_meta,
    const std::array<std::byte, crypto_pwhash_SALTBYTES> &salt_pass);

class Vault {
  friend class Serializator;

public:
  std::expected<void, VaultError> Add(PasswordEntry &&entry);
  std::expected<void, VaultError> Remove(std::size_t index);

  const std::vector<PasswordEntry> &Entries() const;

  Vault() = default;

  void init();

private:
  std::vector<PasswordEntry> entries_;
  Salt meta_salt_;
  Salt master_salt_;
  bool locked_ = false;
};

class Serializator {
public:
  [[nodiscard]]
  static std::expected<void, VaultError>
  serialize(SecureString &&, const EphemeralKey &session_key,
            const std::string &file_path, const Vault &vault);
  [[nodiscard]]
  static std::expected<void, VaultError>
  deserialize(SecureString &&, const EphemeralKey &session_key,
              const std::string &path, Vault &vault);
};

class service {
public:
  static std::expected<void, VaultError> save(SecureString &&,
                                              const EphemeralKey &session_key,
                                              const std::string &name, Vault &);

  static std::expected<void, VaultError> load(SecureString &&,
                                              const EphemeralKey &session_key,
                                              const std::string &name, Vault &);
};
} // namespace vault
