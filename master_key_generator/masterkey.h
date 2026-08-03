#pragma once
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

enum class KeyManagerError {
  FileNotFound,
};

class SecureString {
public:
  explicit SecureString(std::string_view data);

  SecureString(const SecureString &) = delete;
  SecureString &operator=(const SecureString &) = delete;

  SecureString(SecureString &&) noexcept;
  SecureString &operator=(SecureString &&) noexcept;

  void assign(const char *data, std::size_t size) {
    clear();
    if (size == 0 || data == nullptr)
      return;

    data_ = static_cast<char *>(sodium_malloc(size));
    if (!data_) {
      throw std::bad_alloc();
    }

    std::copy_n(data, size, data_);
    size_ = size;
  }

  void clear() noexcept {
    if (data_) {
      sodium_free(data_);
      data_ = nullptr;
    }
    size_ = 0;
  }

  [[nodiscard]] char *data() const noexcept { return data_; }

  [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

  friend std::istream &operator>>(std::istream &is, SecureString &ss) {
    std::string buf;
    if (is >> buf) {
      ss.assign(buf.data(), buf.size());
      sodium_memzero(buf.data(), buf.size());
    }
    return is;
  }

  ~SecureString();

  std::string_view view() const noexcept;

  std::size_t size() const noexcept;

private:
  char *data_ = nullptr;
  std::size_t size_ = 0;
};

#define MESSAGE ((const unsigned char *)"test")
#define MESSAGE_LEN 32
#define CIPHERTEXT_LEN (crypto_secretbox_MACBYTES + MESSAGE_LEN)

using Salt = std::array<std::byte, crypto_pwhash_SALTBYTES>;

using Nonce = std::array<std::byte, crypto_secretbox_NONCEBYTES>;

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

class SaltManager {
public:
  static void saveToFile(const Salt &salt, const std::string &file_path) {
    std::ofstream salt_file(file_path, std::ios::binary);
    salt_file.write(reinterpret_cast<const char *>(salt.data()), salt.size());
  }

  static Salt generateSalt() {
    Salt salt;

    randombytes_buf(salt.data(), salt.size());
    return salt;
  }

  [[nodiscard]]
  static std::expected<Salt, KeyManagerError>
  getSaltFromFile(const std::string &file_path) {
    Salt salt;

    std::ifstream salt_file(file_path, std::ios::binary);

    if (!salt_file) {
      return std::unexpected(KeyManagerError::FileNotFound);
    }

    salt_file.read(reinterpret_cast<char *>(salt.data()), salt.size());

    if (!salt_file) {
      return std::unexpected(KeyManagerError::FileNotFound);
    }

    return salt;
  }
};

class NonceManager {
public:
  static Nonce generate() {
    Nonce nonce;
    randombytes_buf(nonce.data(), nonce.size());
    return nonce;
  }

  [[nodiscard]]
  static std::expected<Nonce, KeyManagerError>
  read_from_file(const std::string &file_path) {
    Nonce nonce;
    try {
      std::ifstream nonce_file(file_path, std::ios::binary);
      nonce_file.read(reinterpret_cast<char *>(nonce.data()), nonce.size());
    } catch (std::exception &e) {
      return std::unexpected(KeyManagerError::FileNotFound);
    }
    return nonce;
  }

  static void write_to_file(const std::string &file_path, const Nonce &nonce) {
    std::ofstream nonce_file(file_path, std::ios::binary);
    nonce_file.write(reinterpret_cast<const char *>(nonce.data()),
                     nonce.size());
  }
};
