#include "master_key_generator/ephemeralkey.h"

EphemeralKey::EphemeralKey() {
  sodium_mlock(key_.data(), key_.size());
  randombytes_buf(key_.data(), key_.size());
}

EphemeralKey::~EphemeralKey() noexcept {
  sodium_memzero(key_.data(), key_.size());
  sodium_munlock(key_.data(), key_.size());
}

const unsigned char *EphemeralKey::data() const noexcept {
  return reinterpret_cast<const unsigned char *>(key_.data());
}
