#include "masterkey.h"
#include <algorithm>
#include <iostream>
#include <utility>

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

  std::visit(
      [&password, &key](const auto &salt_value) {
        if (crypto_pwhash(key.data(), key.size(), password.view().data(),
                          password.view().size(),
                          reinterpret_cast<const unsigned char *>(
                              salt_value.data()),
                          kPwhashOpsLimit, kPwhashMemLimit, kPwhashAlgorithm) !=
            0) {
          throw KDFError{""};
        }
      },
      salt);

  return key;
}
