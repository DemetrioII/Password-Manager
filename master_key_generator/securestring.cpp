#include "master_key_generator/securestring.h"
#include <cstring>
#include <exception>
#include <stdexcept>

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
  make_readonly();
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
    clear();
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
  make_readonly();
}

void SecureString::make_readonly() noexcept {
  if (data_ == nullptr)
    return;
  if (sodium_mprotect_readonly(data_) != 0)
    std::terminate();
}

void SecureString::make_writable() {
  if (data_ == nullptr)
    return;
  if (sodium_mprotect_readwrite(data_) != 0)
    throw std::runtime_error("SecureString: failed to make buffer writable");
}

void SecureString::clear() noexcept {
  if (data_) {
    // If the page cannot be made writable, do not attempt to zero it (that
    // would crash on a PROT_READ page); sodium_free() releases it regardless.
    if (sodium_mprotect_readwrite(data_) == 0)
      sodium_memzero(data_, size_);
    sodium_free(data_);
    data_ = nullptr;
  }
  size_ = 0;
}

SecureString::~SecureString() { clear(); }

bool operator==(const SecureString &lhs, const SecureString &rhs) {
  if (lhs.size_ != rhs.size_)
    return false;
  if (lhs.size_ == 0)
    return true;
  return sodium_memcmp(lhs.data_, rhs.data_, lhs.size_) == 0;
}
