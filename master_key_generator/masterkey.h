#pragma once
#include <array>
#include <fstream>
#include <optional>
#include <sodium.h>
#include <span>
#include <string>

using Salt = std::array<std::byte, crypto_pwhash_SALTBYTES>;

using Nonce = std::array<std::byte, crypto_secretbox_NONCEBYTES>;

class Key {
public:
  std::span<const std::byte> bytes() const noexcept;
  std::span<std::byte> bytes() noexcept;

  unsigned char *data() noexcept;
  const unsigned char *data() const noexcept;

  size_t size() noexcept;

  bool operator==(const Key &other) noexcept { return data_ == other.data_; }

  bool operator!=(const Key &other) noexcept { return data_ != other.data_; }

private:
  std::array<std::byte, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> data_;
};

class MasterKeyManager {
public:
  static std::optional<Key> deriveKey(const std::string &password,
                                      const Salt &salt);
};

class SaltManager {
public:
  static Salt generateSalt() {
    Salt salt;

    randombytes_buf(salt.data(), salt.size());
    std::ofstream salt_file("salt.bin", std::ios::binary);
    salt_file.write(reinterpret_cast<const char *>(salt.data()), salt.size());
    return salt;
  }

  static Salt getSaltFromFile() {
    Salt salt;
    std::ifstream salt_file("salt.bin", std::ios::binary);
    salt_file.read(reinterpret_cast<char *>(salt.data()), salt.size());
    return salt;
  }
};

class NonceManager {
public:
  static Nonce generate() {
    Nonce nonce;
    randombytes_buf(nonce.data(), sizeof nonce.data());
    return nonce;
  }

  static Nonce read_from_file(const std::string &file_path) {
    Nonce nonce;
    std::ifstream nonce_file(file_path, std::ios::binary);
    nonce_file.read(reinterpret_cast<char *>(nonce.data()), nonce.size());
    return nonce;
  }
};
