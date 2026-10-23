#pragma once
#include "vault_storage/vault_model.hpp"
#include <expected>
#include <fcntl.h>
#include <string_view>
#include <unistd.h>

namespace vault {
// Suffix of the copy of the previous vault file kept next to it before an
// atomic replace. The backup is the same ciphertext, so it needs no extra
// protection beyond the vault's own 0600 permissions.
inline constexpr std::string_view kVaultBackupSuffix = ".bak";
} // namespace vault

class SafeFileWriter {
public:
  static std::expected<void, vault::FileIoError>
  WriteAtomic(const std::filesystem::path &target_path,
              const std::vector<unsigned char> &data);

private:
  static void sync_directory(const std::filesystem::path &dir_path);
};
