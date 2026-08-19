#pragma once
#include <array>
#include <expected>
#include <filesystem>
#include <fstream>
#include <sodium.h>
#include <string>
#include <variant>

enum class KeyManagerError {
  FileNotFound,
};

using Argon2Salt = std::array<std::byte, crypto_pwhash_SALTBYTES>;

using Salt = std::variant<Argon2Salt>;

using XChaCha20Poly1305Nonce =
    std::array<std::byte, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>;

using Nonce = std::variant<XChaCha20Poly1305Nonce>;

class CryptoError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

class InvalidCiphertext : public CryptoError {
  using CryptoError::CryptoError;
};

class AuthenticationFailed : public CryptoError {
  using CryptoError::CryptoError;
};

class KDFError : public std::runtime_error {
  using std::runtime_error::runtime_error;
};

template <typename T> const T &get(const Salt &salt) {
  return std::get<T>(salt);
}

template <typename T> const T &get(const Nonce &nonce) {
  return std::get<T>(nonce);
}

class NonceManager {
public:
  template <typename NonceType> static Nonce generate() {
    NonceType nonce;
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

    std::visit(
        [&nonce_file](auto &nonce) {
          nonce_file.read(reinterpret_cast<char *>(nonce.data()), nonce.size());
        },
        nonce);

    if (!nonce_file) {
      return std::unexpected(KeyManagerError::FileNotFound);
    }
    return nonce;
  }

  static void write_to_file(const std::string &file_path, const Nonce &nonce) {
    std::ofstream nonce_file(file_path, std::ios::binary);
    std::visit(
        [&nonce_file](const auto &nonce) {
          nonce_file.write(reinterpret_cast<const char *>(nonce.data()),
                           nonce.size());
        },
        nonce);
  }
};

class SaltManager {
public:
  static void saveToFile(const Salt &salt, const std::string &file_path) {
    std::ofstream salt_file(file_path, std::ios::binary);
    std::visit(
        [&salt_file](const auto &value) {
          salt_file.write(reinterpret_cast<const char *>(value.data()),
                          value.size());
        },
        salt);
  }

  template <typename SaltType> static Salt generateSalt() {
    SaltType salt;

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

    std::visit(
        [&salt_file](auto &value) {
          salt_file.read(reinterpret_cast<char *>(value.data()), value.size());
        },
        salt);

    if (!salt_file) {
      return std::unexpected(KeyManagerError::FileNotFound);
    }

    return salt;
  }
};
