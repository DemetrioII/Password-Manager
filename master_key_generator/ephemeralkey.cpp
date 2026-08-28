#include "master_key_generator/ephemeralkey.h"
#include <cstring>
#include <sodium.h>

namespace {
constexpr unsigned char EPHEMERAL_SALT[crypto_pwhash_SALTBYTES] = {
    0x50, 0x4d, 0x2d, 0x45, 0x50, 0x48, 0x2d, 0x53,
    0x41, 0x4c, 0x54, 0x2d, 0x30, 0x31, 0x00, 0x00};

constexpr char EPHEMERAL_CONTEXT[crypto_kdf_CONTEXTBYTES] = "PMSESS0";
} // namespace

EphemeralKey::EphemeralKey() { randombytes_buf(key_.data(), key_.size()); }

std::array<unsigned char, crypto_kdf_KEYBYTES>
derive_ephemeral_key(const SecureString &password) {
  std::array<unsigned char, crypto_kdf_KEYBYTES> master_key{};

  if (crypto_pwhash(master_key.data(), master_key.size(), password.data(),
                    password.size(), EPHEMERAL_SALT,
                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_ARGON2ID13) != 0) {
    throw KDFError{""};
  }

  std::array<unsigned char, crypto_kdf_KEYBYTES> ephemeralkey{};

  if (crypto_kdf_derive_from_key(ephemeralkey.data(), ephemeralkey.size(), 0,
                                 EPHEMERAL_CONTEXT, master_key.data()) != 0) {
    sodium_memzero(master_key.data(), master_key.size());
    throw KDFError{""};
  }

  sodium_memzero(master_key.data(), master_key.size());

  return ephemeralkey;
}

EphemeralKey::EphemeralKey(SecureString &&password) {
  sodium_mlock(key_.data(), key_.size());
  auto derived = derive_ephemeral_key(password);
  std::memcpy(key_.data(), derived.data(), key_.size());
  sodium_memzero(derived.data(), derived.size());
}

EphemeralKey::~EphemeralKey() noexcept {
  sodium_memzero(key_.data(), key_.size());
  sodium_munlock(key_.data(), key_.size());
}

EphemeralKey::EphemeralKey(EphemeralKey &&other) noexcept {
  sodium_mlock(key_.data(), key_.size());
  std::memcpy(key_.data(), other.key_.data(), key_.size());
  sodium_memzero(other.key_.data(), other.key_.size());
}

EphemeralKey &EphemeralKey::operator=(EphemeralKey &&other) noexcept {
  if (this == &other)
    return *this;

  sodium_memzero(key_.data(), key_.size());

  std::memcpy(key_.data(), other.key_.data(), key_.size());

  sodium_memzero(other.key_.data(), other.key_.size());
  return *this;
}

const unsigned char *EphemeralKey::data() const noexcept {
  return reinterpret_cast<const unsigned char *>(key_.data());
}

void EphemeralKey::reset() { sodium_memzero(key_.data(), key_.size()); }
