#pragma once
#include "master_key_generator/securestring.h"

#include <cstddef>
#include <expected>
#include <string_view>

// Policy describing the requested password.
//
// Defaults are deliberately non-empty and sane so that `PasswordPolicy{}`
// produces a usable policy rather than a all-false, zero-length one.
struct PasswordPolicy {
  std::size_t length = 16;
  bool lowercase = true;
  bool uppercase = true;
  bool digits = true;
  bool symbols = false;
  // When true, visually ambiguous characters (0/O/o, 1/l/I) are removed from
  // every enabled class before the password is generated.
  bool exclude_ambiguous = false;
};

enum class PasswordError {
  // No character class is enabled: there is no alphabet to draw from.
  NoCharacterClass,
  // length is 0 or smaller than the number of enabled classes (each enabled
  // class is guaranteed at least one character).
  LengthTooShort,
  // length exceeds PasswordGenerator::kMaxLength.
  LengthTooLong,
  // SecureString allocation failed (std::bad_alloc / libsodium failure).
  AllocationFailed,
};

class PasswordGenerator {
public:
  // Absolute bounds. The effective minimum is max(kMinLength, number of
  // enabled classes), because every enabled class must be represented.
  static constexpr std::size_t kMinLength = 1;
  static constexpr std::size_t kMaxLength = 256;

  // Character classes. Symbols are a fixed, documented set:
  //   ! @ # $ % ^ & * ( ) - _ = + [ ] { } ; : , . < > ?
  static constexpr std::string_view kLowercase = "abcdefghijklmnopqrstuvwxyz";
  static constexpr std::string_view kUppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  static constexpr std::string_view kDigits = "0123456789";
  static constexpr std::string_view kSymbols = "!@#$%^&*()-_=+[]{};:,.<>?";
  // Removed from each class when `exclude_ambiguous` is set.
  static constexpr std::string_view kAmbiguous = "0Oo1lI";

  // Generates a password satisfying `policy`, or a PasswordError.
  //
  // Randomness comes from libsodium (`randombytes_uniform`, which performs
  // rejection sampling internally to avoid modulo bias). If a class is enabled
  // it is guaranteed to appear at least once; the result is then shuffled with
  // Fisher-Yates so the guaranteed positions are not predictable.
  [[nodiscard]] static std::expected<SecureString, PasswordError>
  generate(const PasswordPolicy &policy);
};
