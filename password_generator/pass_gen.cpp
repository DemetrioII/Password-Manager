#include "password_generator/pass_gen.h"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <string>
#include <vector>

#include <sodium.h>

namespace {

// Returns a copy of `alphabet` with ambiguous characters removed when
// requested. A copy is needed because the filtered set is no longer a
// contiguous substring of the original literal.
std::string filtered_alphabet(std::string_view alphabet,
                              bool exclude_ambiguous) {
  if (!exclude_ambiguous)
    return std::string{alphabet};

  std::string result;
  result.reserve(alphabet.size());
  for (char c : alphabet) {
    if (PasswordGenerator::kAmbiguous.find(c) == std::string_view::npos)
      result.push_back(c);
  }
  return result;
}

// Uniform draw from a non-empty alphabet. `randombytes_uniform` performs
// rejection sampling internally, so there is no modulo bias.
char pick(std::string_view alphabet) {
  return alphabet[randombytes_uniform(
      static_cast<std::uint32_t>(alphabet.size()))];
}

} // namespace

std::expected<SecureString, PasswordError>
PasswordGenerator::generate(const PasswordPolicy &policy) {
  // Build the list of enabled classes (already ambiguity-filtered) and the
  // union alphabet they all draw from.
  std::vector<std::string> classes;
  std::string union_alphabet;

  const auto add_class = [&](std::string_view alphabet) {
    if (alphabet.empty())
      return;
    classes.push_back(filtered_alphabet(alphabet, policy.exclude_ambiguous));
    union_alphabet.append(classes.back());
  };

  if (policy.lowercase)
    add_class(kLowercase);
  if (policy.uppercase)
    add_class(kUppercase);
  if (policy.digits)
    add_class(kDigits);
  if (policy.symbols)
    add_class(kSymbols);

  if (classes.empty())
    return std::unexpected(PasswordError::NoCharacterClass);
  if (policy.length > kMaxLength)
    return std::unexpected(PasswordError::LengthTooLong);
  // Every enabled class must contribute at least one character, so the length
  // can never be smaller than the number of enabled classes (nor the absolute
  // floor of 1).
  if (policy.length < classes.size() || policy.length < kMinLength)
    return std::unexpected(PasswordError::LengthTooShort);

  try {
    SecureString password(policy.length);
    password.mutate([&](char *out) {
      std::size_t idx = 0;

      // Guarantee one character from each enabled class.
      for (const std::string &cls : classes)
        out[idx++] = pick(cls);

      // Fill the remainder from the union alphabet.
      for (; idx < policy.length; ++idx)
        out[idx] = pick(union_alphabet);

      // Fisher-Yates shuffle so the guaranteed slots are unpredictable.
      for (std::size_t i = policy.length - 1; i > 0; --i) {
        const std::size_t j =
            randombytes_uniform(static_cast<std::uint32_t>(i + 1));
        std::swap(out[i], out[j]);
      }
    });
    return password;
  } catch (const std::exception &) {
    // SecureString allocation (std::bad_alloc / sodium_malloc) or mprotect
    // failure must not escape as an exception.
    return std::unexpected(PasswordError::AllocationFailed);
  }
}
