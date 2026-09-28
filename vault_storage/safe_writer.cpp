#include "vault_storage/safe_writer.h"

#include <cerrno>
#include <cstddef>
#include <string>
#include <vector>

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