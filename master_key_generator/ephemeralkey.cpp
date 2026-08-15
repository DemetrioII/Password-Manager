#include "master_key_generator/ephemeralkey.h"
#include <cstring>

EphemeralKey::EphemeralKey() {
  sodium_mlock(key_.data(), key_.size());
  randombytes_buf(key_.data(), key_.size());
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
