#include "master_key_generator/securestring.h"

SecureString::SecureString(std::string_view data) {
  assign(data.data(), data.size());
}

SecureString::SecureString(std::size_t size) {
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

SecureString::~SecureString() {
  if (data_) {
    sodium_memzero(data_, size_);
    // sodium_mprotect_readwrite(data_);
    sodium_free(data_);
  }
}
