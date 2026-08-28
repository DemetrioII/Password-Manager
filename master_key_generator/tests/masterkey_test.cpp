#include "master_key_generator/masterkey.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <utility>

namespace {

SecureString password(std::string_view value) { return SecureString{value}; }

bool all_zero(const Key &key) {
  return std::all_of(key.bytes().begin(), key.bytes().end(),
                     [](std::byte value) { return value == std::byte{0}; });
}

} // namespace

class SodiumEnvironment : public ::testing::Environment {
public:
  void SetUp() override { ASSERT_EQ(sodium_init(), 0); }
};

TEST(MasterKey, DeriveKeySucceeds) {
  const Salt salt = SaltManager::generateSalt<Argon2Salt>();

  auto result = MasterKeyManager::deriveKey(
      password("correct horse battery staple"), salt);

  ASSERT_TRUE(result.has_value());
}

TEST(MasterKey, DerivedKeyHasCorrectSize) {
  const Salt salt = SaltManager::generateSalt<Argon2Salt>();

  auto result = MasterKeyManager::deriveKey(password("password"), salt);

  ASSERT_TRUE(result.has_value());

  EXPECT_EQ(result->size(), crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
}

TEST(MasterKey, DerivedKeyIsNotZero) {
  const Salt salt = SaltManager::generateSalt<Argon2Salt>();

  auto result = MasterKeyManager::deriveKey(password("password"), salt);

  ASSERT_TRUE(result.has_value());

  EXPECT_FALSE(all_zero(*result));
}

TEST(MasterKey, SamePasswordAndSaltProduceSameKey) {
  const Salt salt = SaltManager::generateSalt<Argon2Salt>();

  auto first = MasterKeyManager::deriveKey(password("password"), salt);

  auto second = MasterKeyManager::deriveKey(password("password"), salt);

  ASSERT_TRUE(first.has_value());
  ASSERT_TRUE(second.has_value());

  EXPECT_EQ(*first, *second);
}

TEST(MasterKey, DifferentPasswordsProduceDifferentKeys) {
  const Salt salt = SaltManager::generateSalt<Argon2Salt>();

  auto first = MasterKeyManager::deriveKey(password("password1"), salt);

  auto second = MasterKeyManager::deriveKey(password("password2"), salt);

  ASSERT_TRUE(first.has_value());
  ASSERT_TRUE(second.has_value());

  EXPECT_NE(*first, *second);
}

TEST(MasterKey, DifferentSaltsProduceDifferentKeys) {
  const Salt first_salt = SaltManager::generateSalt<Argon2Salt>();

  const Salt second_salt = SaltManager::generateSalt<Argon2Salt>();

  auto first = MasterKeyManager::deriveKey(password("password"), first_salt);

  auto second = MasterKeyManager::deriveKey(password("password"), second_salt);

  ASSERT_TRUE(first.has_value());
  ASSERT_TRUE(second.has_value());

  EXPECT_NE(*first, *second);
}

TEST(MasterKey, EmptyPasswordCanBeDerived) {
  const Salt salt = SaltManager::generateSalt<Argon2Salt>();

  auto result = MasterKeyManager::deriveKey(password(""), salt);

  EXPECT_TRUE(result.has_value());
}

TEST(MasterKey, UnicodePasswordCanBeDerived) {
  const Salt salt = SaltManager::generateSalt<Argon2Salt>();

  auto result = MasterKeyManager::deriveKey(password("пароль 😺 密码"), salt);

  EXPECT_TRUE(result.has_value());
}

TEST(Key, DefaultConstructedKeyHasCorrectSize) {
  Key key;

  EXPECT_EQ(key.size(), crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

  EXPECT_NE(key.data(), nullptr);
}

TEST(Key, EqualKeysCompareEqual) {
  const Salt salt = SaltManager::generateSalt<Argon2Salt>();

  auto first = MasterKeyManager::deriveKey(password("password"), salt);

  auto second = MasterKeyManager::deriveKey(password("password"), salt);

  ASSERT_TRUE(first.has_value());
  ASSERT_TRUE(second.has_value());

  EXPECT_TRUE(*first == *second);
  EXPECT_FALSE(*first != *second);
}

TEST(Key, DifferentKeysCompareDifferent) {
  const Salt salt = SaltManager::generateSalt<Argon2Salt>();

  auto first = MasterKeyManager::deriveKey(password("password1"), salt);

  auto second = MasterKeyManager::deriveKey(password("password2"), salt);

  ASSERT_TRUE(first.has_value());
  ASSERT_TRUE(second.has_value());

  EXPECT_FALSE(*first == *second);
  EXPECT_TRUE(*first != *second);
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  ::testing::AddGlobalTestEnvironment(new SodiumEnvironment);
  return RUN_ALL_TESTS();
}
