#include "vault_storage/safe_writer.h"

#include <cerrno>
#include <cstddef>
#include <filesystem>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace {

// Keeps the current target as `<target>.bak` before it is replaced, so a
// damaged main file can still be recovered. A hard link is preferred: it is
// atomic, costs no data copy and the following rename of the main file leaves
// the backup's inode untouched. Filesystems without hard links fall back to a
// real copy performed under a temporary name, so a crash never exposes a
// half-written backup.
std::expected<void, vault::FileIoError>
write_backup(const std::filesystem::path &target_path) {
  std::error_code ec;
  const bool target_exists = std::filesystem::exists(target_path, ec);
  if (ec)
    return std::unexpected(vault::FileIoError::WriteFailed);
  if (!target_exists)
    return {}; // First save: there is nothing to back up yet.

  const std::filesystem::path backup_path =
      target_path.string() + std::string(vault::kVaultBackupSuffix);
  const std::filesystem::path staging_path =
      backup_path.string() + ".tmp." + std::to_string(getpid());

  std::filesystem::remove(staging_path, ec);
  ec.clear();

  if (::link(target_path.c_str(), staging_path.c_str()) != 0) {
    std::filesystem::copy_file(
        target_path, staging_path,
        std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
      std::filesystem::remove(staging_path, ec);
      return std::unexpected(vault::FileIoError::WriteFailed);
    }
  }

  // Hard-linking shares the inode with the old target, and an externally
  // created vault may have wider permissions than we allow.
  if (::chmod(staging_path.c_str(), 0600) != 0) {
    std::filesystem::remove(staging_path, ec);
    return std::unexpected(vault::FileIoError::PermissionSetFailed);
  }

  std::filesystem::rename(staging_path, backup_path, ec);
  if (ec) {
    std::filesystem::remove(staging_path, ec);
    return std::unexpected(vault::FileIoError::WriteFailed);
  }

  return {};
}

} // namespace

std::expected<void, vault::FileIoError>
SafeFileWriter::WriteAtomic(const std::filesystem::path &target_path,
                            const std::vector<unsigned char> &data) {
  // mkstemp creates the file with 0600 permissions regardless of umask and
  // fails if the name already exists, avoiding temp-file collisions.
  std::string pattern = target_path.string() + ".tmp." +
                        std::to_string(getpid()) + ".XXXXXX";
  std::vector<char> templ(pattern.begin(), pattern.end());
  templ.push_back('\0');

  const int fd = ::mkstemp(templ.data());
  if (fd == -1)
    return std::unexpected(vault::FileIoError::TempFileCreationFailed);

  const std::filesystem::path temp_path(templ.data());

  const char *buffer = reinterpret_cast<const char *>(data.data());
  std::size_t remaining = data.size();

  while (remaining > 0) {
    const ssize_t written = ::write(fd, buffer, remaining);
    if (written < 0) {
      if (errno == EINTR)
        continue;
      ::close(fd);
      std::filesystem::remove(temp_path);
      return std::unexpected(vault::FileIoError::WriteFailed);
    }
    if (written == 0)
      break;
    buffer += written;
    remaining -= static_cast<std::size_t>(written);
  }

  if (remaining > 0) {
    ::close(fd);
    std::filesystem::remove(temp_path);
    return std::unexpected(vault::FileIoError::WriteFailed);
  }

  if (::fsync(fd) != 0) {
    ::close(fd);
    std::filesystem::remove(temp_path);
    return std::unexpected(vault::FileIoError::SyncFailed);
  }

  ::close(fd);

  std::error_code ec;

  // Never replace the only copy without a recovery point. A failure here
  // aborts the save instead of silently destroying the previous vault.
  const auto backed_up = write_backup(target_path);
  if (!backed_up) {
    std::filesystem::remove(temp_path, ec);
    return std::unexpected(backed_up.error());
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
  const auto path_to_open = dir_path.empty() ? "." : dir_path;
  const int dir_fd = ::open(path_to_open.c_str(), O_RDONLY | O_DIRECTORY);
  if (dir_fd != -1) {
    ::fsync(dir_fd);
    ::close(dir_fd);
  }
}