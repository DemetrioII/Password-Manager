#pragma once
#include "vault_storage/vault_model.hpp"
#include <expected>
#include <fcntl.h>
#include <unistd.h>

class SafeFileWriter {
public:
  static std::expected<void, vault::FileIoError>
  WriteAtomic(const std::filesystem::path &target_path,
              const std::vector<unsigned char> &data);

private:
  static void sync_directory(const std::filesystem::path &dir_path);
};
