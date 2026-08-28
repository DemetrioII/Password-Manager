#pragma once
#include "securestring.h"
#include "utils.h"
#include <array>
#include <sodium.h>
#include <stdexcept>

class EphemeralKey {
public:
  EphemeralKey();
  EphemeralKey(SecureString &&);

  ~EphemeralKey() noexcept;

  EphemeralKey(const EphemeralKey &) = delete;
  EphemeralKey &operator=(const EphemeralKey &) = delete;

  EphemeralKey(EphemeralKey &&other) noexcept;
  EphemeralKey &operator=(EphemeralKey &&other) noexcept;

  [[nodiscard]] const unsigned char *data() const noexcept;

  void reset();

  [[nodiscard]] static constexpr std::size_t size() noexcept {
    return crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
  }

private:
  std::array<std::byte, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> key_;
};
