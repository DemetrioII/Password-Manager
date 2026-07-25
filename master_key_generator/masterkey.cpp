#include "masterkey.h"
#include <algorithm>
#include <iostream>
#include <utility>

SecureString::SecureString(std::string_view data) {
  assign(data.data(), data.size());
}

std::string SecureString::view() const noexcept { return data_; }

std::size_t SecureString::size() const noexcept { return size_; }

SecureString::SecureString(SecureString &&other) noexcept
    : data_(std::exchange(other.data_, nullptr)),
      size_(std::exchange(other.size_, 0)) {}

SecureString &SecureString::operator=(SecureString &&other) noexcept {
  data_ = std::move(other.data_);
  size_ = std::move(other.size_);
  return *this;
}

SecureString::~SecureString() { sodium_memzero(data_, size_); }

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
