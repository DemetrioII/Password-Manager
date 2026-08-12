#pragma once
#include "master_key_generator/securestring.h"
#include <algorithm>
#include <array>
#include <expected>
#include <fstream>
#include <optional>
#include <sodium.h>
#include <span>
#include <sstream>
#include <string>
#include <utility>

#include "master_key_generator/utils.h"

class Key {
public:
  Key() { sodium_mlock(data_.data(), data_.size()); }

  ~Key() {
    sodium_memzero(data_.data(), data_.size());
    sodium_munlock(data_.data(), data_.size());
  }

  Key(const Key &) = delete;
  Key &operator=(const Key &) = delete;

  Key(Key &&other) noexcept : data_(other.data_) {
    sodium_memzero(other.data_.data(), other.data_.size());
    sodium_mlock(data_.data(), data_.size());
    sodium_munlock(other.data_.data(), other.data_.size());
  }

  Key &operator=(Key &&other) noexcept {
    if (this != &other) {
      sodium_memzero(data_.data(), data_.size());

      data_ = other.data_;

      sodium_mlock(data_.data(), data_.size());

      sodium_memzero(other.data_.data(), other.data_.size());
    }
    return *this;
  }

  std::span<const std::byte> bytes() const noexcept;
  std::span<std::byte> bytes() noexcept;

  unsigned char *data() noexcept;
  const unsigned char *data() const noexcept;

  size_t size() const noexcept;

  bool operator==(const Key &other) const noexcept {
    return sodium_memcmp(data(), other.data(), size()) == 0;
  }

  bool operator!=(const Key &other) const noexcept {
    return sodium_memcmp(data(), other.data(), size()) != 0;
  }

private:
  std::array<std::byte, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> data_;
};

class MasterKeyManager {
public:
  [[nodiscard]]
  static std::optional<Key> deriveKey(SecureString &&password,
                                      const Salt &salt);
};
