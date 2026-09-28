#include "master_key_generator/ephemeralkey.h"
#include <cstring>
#include <sodium.h>

namespace {
constexpr char EPHEMERAL_CONTEXT[crypto_kdf_CONTEXTBYTES] = "PMSESS0";
} // namespace

EphemeralKey::EphemeralKey() { randombytes_buf(key_.data(), key_.size()); }

std::array<unsigned char, crypto_kdf_KEYBYTES>
derive_ephemeral_key(const SecureString &password, const Argon2Salt &salt) {
  std::array<unsigned char, crypto_kdf_KEYBYTES> master_key{};

  if (crypto_pwhash(master_key.data(), master_key.size(), password.data(),
                    password.size(),
                    reinterpret_cast<const unsigned char *>(salt.data()),
                    kPwhashOpsLimit, kPwhashMemLimit, kPwhashAlgorithm) != 0) {
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

EphemeralKey::EphemeralKey(SecureString &&password, const Argon2Salt &salt) {
  lock_memory_or_fail(key_.data(), key_.size());
  auto derived = derive_ephemeral_key(password, salt);
  std::memcpy(key_.data(), derived.data(), key_.size());
  sodium_memzero(derived.data(), derived.size());
}

EphemeralKey::~EphemeralKey() noexcept {
  sodium_memzero(key_.data(), key_.size());
  sodium_munlock(key_.data(), key_.size());
}

EphemeralKey::EphemeralKey(EphemeralKey &&other) noexcept {
  lock_memory_or_fail(key_.data(), key_.size());
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
