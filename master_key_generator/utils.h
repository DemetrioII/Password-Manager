#pragma once
#include <array>
#include <expected>
#include <filesystem>
#include <fstream>
#include <sodium.h>
#include <string>

enum class KeyManagerError {
  FileNotFound,
};

#define MESSAGE ((const unsigned char *)"test")
#define MESSAGE_LEN 32
#define CIPHERTEXT_LEN (crypto_secretbox_MACBYTES + MESSAGE_LEN)

using Salt = std::array<std::byte, crypto_pwhash_SALTBYTES>;

using Nonce = std::array<std::byte, crypto_secretbox_NONCEBYTES>;

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
    std::ifstream nonce_file(file_path, std::ios::binary);

    if (!nonce_file) {
      return std::unexpected(KeyManagerError::FileNotFound);
    }

    nonce_file.read(reinterpret_cast<char *>(nonce.data()), nonce.size());

    if (!nonce_file) {
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
