#pragma once
#include <array>
#include <sodium.h>
#include <stdexcept>

class EphemeralKey {
public:
  EphemeralKey();

  ~EphemeralKey() noexcept;

  EphemeralKey(const EphemeralKey &) = delete;
  EphemeralKey &operator=(const EphemeralKey &) = delete;

  EphemeralKey(EphemeralKey &&other);
  EphemeralKey &operator=(EphemeralKey &&other);

  [[nodiscard]] const unsigned char *data() const noexcept;

  [[nodiscard]] static constexpr std::size_t size() noexcept {
    return crypto_secretbox_KEYBYTES;
  }

private:
  std::array<std::byte, crypto_secretbox_KEYBYTES> key_;
};
