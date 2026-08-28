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

  key = std::move(key);

  EXPECT_EQ(std::memcmp(key.data(), before.data(), before.size()), 0);
}
