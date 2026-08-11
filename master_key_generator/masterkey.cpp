#include "masterkey.h"
#include <algorithm>
#include <iostream>
#include <utility>

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
    sodium_free(data_);
  }
}

std::span<std::byte> Key::bytes() noexcept { return data_; }

std::span<const std::byte> Key::bytes() const noexcept { return data_; }

const unsigned char *Key::data() const noexcept {
  return reinterpret_cast<const unsigned char *>(data_.data());
}

unsigned char *Key::data() noexcept {
  return reinterpret_cast<unsigned char *>(data_.data());
}

size_t Key::size() const noexcept { return data_.size(); }

std::optional<Key> MasterKeyManager::deriveKey(SecureString &&password,
                                               const Salt &salt) {
  Key key;

  if (crypto_pwhash(key.data(), key.size(), password.view().data(),
                    password.view().size(),
                    reinterpret_cast<const unsigned char *>(salt.data()),
                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_DEFAULT) != 0) {
    return std::nullopt;
  }

  return key;
}
