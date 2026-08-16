#include "vault_storage/safe_writer.h"

std::expected<void, vault::FileIoError>
SafeFileWriter::WriteAtomic(const std::filesystem::path &target_path,
                            const std::vector<unsigned char> &data) {
  std::filesystem::path temp_path = target_path;
  temp_path += ".tmp." + std::to_string(getpid());

  std::ofstream file(temp_path, std::ios::binary | std::ios::trunc);
  if (!file.is_open()) {
    return std::unexpected(vault::FileIoError::TempFileCreationFailed);
  }

  std::error_code ec;
  std::filesystem::permissions(temp_path,
                               std::filesystem::perms::owner_read |
                                   std::filesystem::perms::owner_write,
                               std::filesystem::perm_options::replace, ec);

  if (ec) {
    std::filesystem::remove(temp_path, ec);
    return std::unexpected(vault::FileIoError::PermissionSetFailed);
  }

  file.write(reinterpret_cast<const char *>(data.data()), data.size());
  if (!file.good()) {
    file.close();
    std::filesystem::remove(temp_path, ec);
    return std::unexpected(vault::FileIoError::WriteFailed);
  }

  file.flush();

  file.close();

  int fd = ::open(temp_path.c_str(), O_WRONLY);
  if (fd != -1) {
    ::fsync(fd);
    ::close(fd);
  } else {
    std::filesystem::remove(temp_path, ec);
    return std::unexpected(vault::FileIoError::SyncFailed);
  }

  std::filesystem::rename(temp_path, target_path, ec);
  if (ec) {
    std::filesystem::remove(temp_path, ec);
    return std::unexpected(vault::FileIoError::RenameFailed);
  }

  sync_directory(target_path.parent_path());

  return {};
}

void SafeFileWriter::sync_directory(const std::filesystem::path &dir_path) {
  auto path_to_open = dir_path.empty() ? "." : dir_path;
  int dir_fd = ::open(dir_path.c_str(), O_RDONLY | O_DIRECTORY);
  if (dir_fd != -1) {
    ::fsync(dir_fd);
    ::close(dir_fd);
  }
}
