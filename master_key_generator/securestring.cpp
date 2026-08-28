#include "master_key_generator/securestring.h"
#include <cstring>

SecureString::SecureString(std::string_view data) {
  assign(data.data(), data.size());
}

SecureString::SecureString(std::size_t size) {
  if (size == 0)
    return;

  data_ = static_cast<char *>(sodium_malloc(size));
  if (!data_)
    throw std::bad_alloc();
  size_ = size;
}

std::string_view SecureString::view() const noexcept {
  return std::string_view{data_, size_};
}

std::size_t SecureString::size() const noexcept { return size_; }

SecureString::SecureString(SecureString &&other) noexcept
    : data_(std::exchange(other.data_, nullptr)),
      size_(std::exchange(other.size_, 0)) {}

SecureString &SecureString::operator=(SecureString &&other) noexcept {
  if (this != &other) {
    if (data_) {
      sodium_memzero(data_, size_);
      sodium_free(data_);
    }
    data_ = std::exchange(other.data_, nullptr);
    size_ = std::exchange(other.size_, 0);
  }
  return *this;
}

void SecureString::assign(const char *data, std::size_t size) {
  clear();
  if (size == 0 || data == nullptr)
    return;

  data_ = static_cast<char *>(sodium_malloc(size));
  if (!data_) {
    throw std::bad_alloc();
  }

  std::copy_n(data, size, data_);
  size_ = size;
  // sodium_mprotect_readonly(data_);
}

void SecureString::clear() noexcept {
  if (data_) {
    sodium_memzero(data_, size_);
    sodium_free(data_);
    data_ = nullptr;
  }
  size_ = 0;
}

SecureString::~SecureString() {
  if (data_) {
    sodium_memzero(data_, size_);
    // sodium_mprotect_readwrite(data_);
    sodium_free(data_);
  }
}

bool operator==(const SecureString &lhs, const SecureString &rhs) {
  if (lhs.size_ != rhs.size_)
    return false;
  if (strncmp(lhs.data_, rhs.data_, std::min(lhs.size_, rhs.size_)) == 0)
    return true;
  return false;
}
