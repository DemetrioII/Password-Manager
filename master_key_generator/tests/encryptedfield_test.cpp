#include "master_key_generator/encryptedfield.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <sodium.h>

class SodiumEnvironment : public ::testing::Environment {
public:
  void SetUp() override { ASSERT_EQ(sodium_init(), 0); }
};

TEST(EncryptedField, EncryptDecryptRoundTrip) {
  EphemeralKey key;

  SecureString plaintext{"my very secret password"};

  const auto encrypted = EncryptedField::encrypt(plaintext, key);

  const auto decrypted = encrypted.decrypt(key);

  EXPECT_EQ(decrypted.view(), plaintext.view());
}

TEST(EncryptedField, EmptyPlaintextRoundTrip) {
  EphemeralKey key;

  SecureString plaintext{std::size_t{0}};

  const auto encrypted = EncryptedField::encrypt(plaintext, key);

  const auto decrypted = encrypted.decrypt(key);

  EXPECT_TRUE(decrypted.empty());
}

TEST(EncryptedField, UnicodeRoundTrip) {
  EphemeralKey key;

  SecureString plaintext{"пароль 😺 密码 🔐"};

  const auto encrypted = EncryptedField::encrypt(plaintext, key);

  const auto decrypted = encrypted.decrypt(key);

  EXPECT_EQ(decrypted.view(), plaintext.view());
}

TEST(EncryptedField, BinaryDataRoundTrip) {
  EphemeralKey key;

  constexpr std::array<char, 7> bytes{'\0',   '\x01', '\x02', '\x7f',
                                      '\xff', '\0',   '\xab'};

  SecureString plaintext{std::string(bytes.data(), bytes.size())};

  const auto encrypted = EncryptedField::encrypt(plaintext, key);

  const auto decrypted = encrypted.decrypt(key);

  ASSERT_EQ(decrypted.size(), bytes.size());

  // EXPECT_EQ(std::string_view{decrypted.data(), decrypted.size()},
  // std::string_view{bytes.data(), bytes.size()});
}

TEST(EncryptedField, EncryptionDoesNotModifyPlaintext) {
  EphemeralKey key;

  SecureString plaintext{"super secret"};

  const auto before = std::string{plaintext.data(), plaintext.size()};

  [[maybe_unused]]
  const auto encrypted = EncryptedField::encrypt(plaintext, key);

  EXPECT_EQ(plaintext.view(), before);
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);

  ::testing::AddGlobalTestEnvironment(new SodiumEnvironment);

  return RUN_ALL_TESTS();
}
