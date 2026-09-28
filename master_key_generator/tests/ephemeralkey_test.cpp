#include "master_key_generator/ephemeralkey.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <utility>

TEST(EphemeralKey, HasCorrectSize) {
  EphemeralKey key;

  EXPECT_EQ(EphemeralKey::size(), crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

  EXPECT_NE(key.data(), nullptr);
}

TEST(EphemeralKey, TwoKeysAreNotDifferent) {
  EphemeralKey first;
  EphemeralKey second;

  EXPECT_NE(std::memcmp(first.data(), second.data(), EphemeralKey::size()), 0);
}

TEST(EphemeralKey, DerivesSameKeyFromSamePasswordAndSalt) {
  const Salt salt = SaltManager::generateSalt<Argon2Salt>();

  EphemeralKey first{SecureString{"correct horse battery staple"},
                     get<Argon2Salt>(salt)};
  EphemeralKey second{SecureString{"correct horse battery staple"},
                      get<Argon2Salt>(salt)};

  EXPECT_EQ(std::memcmp(first.data(), second.data(), EphemeralKey::size()), 0);
}

TEST(EphemeralKey, DifferentSaltsProduceDifferentKeys) {
  const Salt salt1 = SaltManager::generateSalt<Argon2Salt>();
  const Salt salt2 = SaltManager::generateSalt<Argon2Salt>();

  EphemeralKey first{SecureString{"correct horse battery staple"},
                     get<Argon2Salt>(salt1)};
  EphemeralKey second{SecureString{"correct horse battery staple"},
                      get<Argon2Salt>(salt2)};

  EXPECT_NE(std::memcmp(first.data(), second.data(), EphemeralKey::size()), 0);
}

TEST(EphemeralKey, DifferentPasswordsProduceDifferentKeys) {
  const Salt salt = SaltManager::generateSalt<Argon2Salt>();

  EphemeralKey first{SecureString{"password1"}, get<Argon2Salt>(salt)};
  EphemeralKey second{SecureString{"password2"}, get<Argon2Salt>(salt)};

  EXPECT_NE(std::memcmp(first.data(), second.data(), EphemeralKey::size()), 0);
}

TEST(EphemeralKey, MoveConstructorTransfersKey) {
  EphemeralKey original;

  std::array<unsigned char, EphemeralKey::size()> original_bytes;
  std::memcpy(original_bytes.data(), original.data(), original_bytes.size());

  EphemeralKey moved{std::move(original)};

  EXPECT_EQ(
      std::memcmp(moved.data(), original_bytes.data(), original_bytes.size()),
      0);
}

TEST(EphemeralKey, MovedFromKeyIsZeroed) {
  EphemeralKey original;

  EphemeralKey moved{std::move(original)};

  std::array<unsigned char, EphemeralKey::size()> zeros{};

  EXPECT_EQ(std::memcmp(original.data(), zeros.data(), zeros.size()), 0);
}

TEST(EphemeralKey, MoveAssignmentTransfersKey) {
  EphemeralKey source;

  std::array<unsigned char, EphemeralKey::size()> source_bytes;
  std::memcpy(source_bytes.data(), source.data(), source_bytes.size());

  EphemeralKey destination;

  destination = std::move(source);

  EXPECT_EQ(
      std::memcmp(destination.data(), source_bytes.data(), source_bytes.size()),
      0);
}

TEST(EphemeralKey, MoveAssignmentZeroesSource) {
  EphemeralKey source;
  EphemeralKey destination;

  destination = std::move(source);

  std::array<unsigned char, EphemeralKey::size()> zeros{};

  EXPECT_EQ(std::memcmp(source.data(), zeros.data(), zeros.size()), 0);
}

TEST(EphemeralKey, SelfMoveAssignmentDoesNothing) {
  EphemeralKey key;

  std::array<unsigned char, EphemeralKey::size()> before;
  std::memcpy(before.data(), key.data(), before.size());

  #pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wself-move"
  key = std::move(key);
#pragma GCC diagnostic pop

  EXPECT_EQ(std::memcmp(key.data(), before.data(), before.size()), 0);
}

class SodiumEnvironment : public ::testing::Environment {
public:
  void SetUp() override { ASSERT_EQ(sodium_init(), 0); }
};

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);

  ::testing::AddGlobalTestEnvironment(new SodiumEnvironment);
  return RUN_ALL_TESTS();
}
