#include "password_generator/pass_gen.h"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <string>
#include <string_view>

#include <sodium.h>

namespace {

class SodiumEnvironment : public ::testing::Environment {
public:
  void SetUp() override { ASSERT_EQ(sodium_init(), 0); }
};

std::string to_std_string(const SecureString &secret) {
  return std::string{secret.view()};
}

bool contains(std::string_view haystack, char needle) {
  return haystack.find(needle) != std::string_view::npos;
}

// Rebuilds the union alphabet implied by a policy, applying the same
// ambiguous-character filter as the generator.
std::string expected_alphabet(const PasswordPolicy &policy) {
  std::string result;
  const auto add = [&](std::string_view alphabet) {
    for (char c : alphabet) {
      if (policy.exclude_ambiguous &&
          contains(PasswordGenerator::kAmbiguous, c))
        continue;
      result.push_back(c);
    }
  };

  if (policy.lowercase)
    add(PasswordGenerator::kLowercase);
  if (policy.uppercase)
    add(PasswordGenerator::kUppercase);
  if (policy.digits)
    add(PasswordGenerator::kDigits);
  if (policy.symbols)
    add(PasswordGenerator::kSymbols);
  return result;
}

std::size_t enabled_class_count(const PasswordPolicy &policy) {
  return static_cast<std::size_t>(policy.lowercase) +
         static_cast<std::size_t>(policy.uppercase) +
         static_cast<std::size_t>(policy.digits) +
         static_cast<std::size_t>(policy.symbols);
}

} // namespace

TEST(PasswordGenerator, ResultLengthMatchesPolicy) {
  PasswordPolicy policy{};
  policy.length = 24;

  auto result = PasswordGenerator::generate(policy);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->size(), policy.length);
}

TEST(PasswordGenerator, DefaultPolicyLengthIsSixteen) {
  PasswordPolicy policy{};

  auto result = PasswordGenerator::generate(policy);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->size(), 16u);
}

TEST(PasswordGenerator, IncludesEveryEnabledClassOverManyRuns) {
  PasswordPolicy policy{};
  policy.length = 20;
  policy.lowercase = true;
  policy.uppercase = true;
  policy.digits = true;
  policy.symbols = true;

  for (int run = 0; run < 500; ++run) {
    auto result = PasswordGenerator::generate(policy);
    ASSERT_TRUE(result.has_value());
    const std::string password = to_std_string(*result);

    for (char c : password) {
      if (contains(PasswordGenerator::kLowercase, c) ||
          contains(PasswordGenerator::kUppercase, c) ||
          contains(PasswordGenerator::kDigits, c) ||
          contains(PasswordGenerator::kSymbols, c))
        continue;
      FAIL() << "unexpected character in password";
    }

    bool has_lower = false, has_upper = false, has_digit = false,
         has_symbol = false;
    for (char c : password) {
      has_lower |= contains(PasswordGenerator::kLowercase, c);
      has_upper |= contains(PasswordGenerator::kUppercase, c);
      has_digit |= contains(PasswordGenerator::kDigits, c);
      has_symbol |= contains(PasswordGenerator::kSymbols, c);
    }
    EXPECT_TRUE(has_lower);
    EXPECT_TRUE(has_upper);
    EXPECT_TRUE(has_digit);
    EXPECT_TRUE(has_symbol);
  }
}

TEST(PasswordGenerator, SingleEnabledClassProducesOnlyThatClass) {
  PasswordPolicy policy{};
  policy.length = 32;
  policy.lowercase = true;
  policy.uppercase = false;
  policy.digits = false;
  policy.symbols = false;

  for (int run = 0; run < 200; ++run) {
    auto result = PasswordGenerator::generate(policy);
    ASSERT_TRUE(result.has_value());
    const std::string password = to_std_string(*result);

    EXPECT_TRUE(password.find_first_not_of(PasswordGenerator::kLowercase) ==
                std::string::npos);
  }
}

TEST(PasswordGenerator, AllCharactersStayWithinUnionAlphabet) {
  PasswordPolicy policy{};
  policy.length = 40;
  policy.lowercase = true;
  policy.uppercase = true;
  policy.digits = true;
  policy.symbols = true;

  const std::string alphabet = expected_alphabet(policy);

  for (int run = 0; run < 1000; ++run) {
    auto result = PasswordGenerator::generate(policy);
    ASSERT_TRUE(result.has_value());
    const std::string password = to_std_string(*result);

    for (char c : password)
      ASSERT_NE(alphabet.find(c), std::string::npos);
  }
}

TEST(PasswordGenerator, ExcludeAmbiguousRemovesAmbiguousCharacters) {
  PasswordPolicy policy{};
  policy.length = 32;
  policy.lowercase = true;
  policy.uppercase = true;
  policy.digits = true;
  policy.symbols = true;
  policy.exclude_ambiguous = true;

  for (int run = 0; run < 500; ++run) {
    auto result = PasswordGenerator::generate(policy);
    ASSERT_TRUE(result.has_value());
    const std::string password = to_std_string(*result);

    for (char c : password) {
      if (contains(PasswordGenerator::kAmbiguous, c))
        FAIL() << "ambiguous character survived filtering";
    }
  }
}

TEST(PasswordGenerator, ExcludeAmbiguousKeepsEveryClassPresent) {
  PasswordPolicy policy{};
  policy.length = 16;
  policy.lowercase = true;
  policy.uppercase = true;
  policy.digits = true;
  policy.symbols = true;
  policy.exclude_ambiguous = true;

  for (int run = 0; run < 500; ++run) {
    auto result = PasswordGenerator::generate(policy);
    ASSERT_TRUE(result.has_value());
    const std::string password = to_std_string(*result);

    bool has_lower = false, has_upper = false, has_digit = false,
         has_symbol = false;
    for (char c : password) {
      if (contains(PasswordGenerator::kAmbiguous, c))
        FAIL() << "ambiguous character survived filtering";
      has_lower |= contains(PasswordGenerator::kLowercase, c);
      has_upper |= contains(PasswordGenerator::kUppercase, c);
      has_digit |= contains(PasswordGenerator::kDigits, c);
      has_symbol |= contains(PasswordGenerator::kSymbols, c);
    }
    EXPECT_TRUE(has_lower);
    EXPECT_TRUE(has_upper);
    EXPECT_TRUE(has_digit);
    EXPECT_TRUE(has_symbol);
  }
}

TEST(PasswordGenerator, EmptyPolicyIsRejected) {
  PasswordPolicy policy{};
  policy.lowercase = false;
  policy.uppercase = false;
  policy.digits = false;
  policy.symbols = false;

  auto result = PasswordGenerator::generate(policy);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), PasswordError::NoCharacterClass);
}

TEST(PasswordGenerator, ZeroLengthIsRejected) {
  PasswordPolicy policy{};
  policy.length = 0;

  auto result = PasswordGenerator::generate(policy);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), PasswordError::LengthTooShort);
}

TEST(PasswordGenerator, LengthSmallerThanClassCountIsRejected) {
  PasswordPolicy policy{};
  policy.length = 3;
  policy.lowercase = true;
  policy.uppercase = true;
  policy.digits = true;
  policy.symbols = true;

  auto result = PasswordGenerator::generate(policy);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), PasswordError::LengthTooShort);
}

TEST(PasswordGenerator, LengthGreaterThanMaxIsRejected) {
  PasswordPolicy policy{};
  policy.length = PasswordGenerator::kMaxLength + 1;

  auto result = PasswordGenerator::generate(policy);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), PasswordError::LengthTooLong);
}

TEST(PasswordGenerator, LengthEqualToClassCountIsAccepted) {
  PasswordPolicy policy{};
  policy.length = 4;
  policy.lowercase = true;
  policy.uppercase = true;
  policy.digits = true;
  policy.symbols = true;

  auto result = PasswordGenerator::generate(policy);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->size(), 4u);
}

TEST(PasswordGenerator, LengthEqualToMaxIsAccepted) {
  PasswordPolicy policy{};
  policy.length = PasswordGenerator::kMaxLength;
  policy.lowercase = true;
  policy.uppercase = true;
  policy.digits = true;
  policy.symbols = true;

  auto result = PasswordGenerator::generate(policy);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->size(), PasswordGenerator::kMaxLength);
  EXPECT_EQ(enabled_class_count(policy), 4u);
}

TEST(PasswordGenerator, CharacterDistributionIsApproximatelyUniform) {
  PasswordPolicy policy{};
  policy.length = 64;
  policy.lowercase = true;
  policy.uppercase = true;
  policy.digits = true;
  policy.symbols = true;

  const std::string alphabet = expected_alphabet(policy);
  ASSERT_FALSE(alphabet.empty());

  constexpr int kRuns = 500;
  std::array<int, 256> counts{};
  for (int run = 0; run < kRuns; ++run) {
    auto result = PasswordGenerator::generate(policy);
    ASSERT_TRUE(result.has_value());
    for (char c : to_std_string(*result))
      ++counts[static_cast<unsigned char>(c)];
  }

  const double total =
      static_cast<double>(kRuns) * static_cast<double>(policy.length);
  const double expected = total / static_cast<double>(alphabet.size());
  // Generous band (roughly +/- 9 sigma) to avoid flakiness while still catching
  // gross bias such as a missing or heavily under-sampled character.
  const double lower = expected * 0.5;
  const double upper = expected * 2.0;

  for (char c : alphabet) {
    const int count = counts[static_cast<unsigned char>(c)];
    EXPECT_GT(count, 0) << "character missing from distribution";
    EXPECT_GE(static_cast<double>(count), lower);
    EXPECT_LE(static_cast<double>(count), upper);
  }
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);

  ::testing::AddGlobalTestEnvironment(new SodiumEnvironment);

  return RUN_ALL_TESTS();
}
