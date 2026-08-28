#include "master_key_generator/utils.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>

namespace {

class SaltTest : public ::testing::Test {
protected:
  std::filesystem::path path =
      std::filesystem::temp_directory_path() / "password_manager_salt_test";

  void TearDown() override { std::filesystem::remove(path); }
};

} // namespace

TEST_F(SaltTest, GenerateHasCorrectSize) {
  const auto salt = SaltManager::generateSalt<Argon2Salt>();

  std::visit(
      [](const auto &salt) { EXPECT_EQ(salt.size(), crypto_pwhash_SALTBYTES); },
      salt);
}

TEST_F(SaltTest, GeneratedSaltIsNotAllZeroes) {
  const auto salt = SaltManager::generateSalt<Argon2Salt>();

  std::visit(
      [](const auto &salt) {
        const bool all_zero =
            std::all_of(salt.begin(), salt.end(),
                        [](std::byte value) { return value == std::byte{0}; });

        EXPECT_FALSE(all_zero);
      },
      salt);
}

TEST_F(SaltTest, TwoGeneratedSaltsAreDifferent) {
  const auto first = SaltManager::generateSalt<Argon2Salt>();

  const auto second = SaltManager::generateSalt<Argon2Salt>();

  EXPECT_NE(first, second);
}

TEST_F(SaltTest, WriteThenReadReturnsSameSalt) {
  const auto original = SaltManager::generateSalt<Argon2Salt>();

  SaltManager::saveToFile(original, path.string());

  const auto result = SaltManager::getSaltFromFile(path.string());

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(*result, original);
}

TEST_F(SaltTest, MissingFileReturnsError) {
  const auto result = SaltManager::getSaltFromFile(path.string());

  ASSERT_FALSE(result.has_value());

  EXPECT_EQ(result.error(), KeyManagerError::FileNotFound);
}

TEST_F(SaltTest, TruncatedFileReturnsError) {
  {
    std::ofstream file(path, std::ios::binary);

    const std::array<std::byte, 4> garbage{};
    file.write(reinterpret_cast<const char *>(garbage.data()), garbage.size());
  }

  const auto result = SaltManager::getSaltFromFile(path.string());

  EXPECT_FALSE(result.has_value());
}

TEST_F(SaltTest, EmptyFileReturnsError) {
  {
    std::ofstream file(path, std::ios::binary);
  }

  const auto result = SaltManager::getSaltFromFile(path.string());

  EXPECT_FALSE(result.has_value());
}

TEST_F(SaltTest, ExtraBytesAreIgnored) {
  const auto original = SaltManager::generateSalt<Argon2Salt>();

  {
    std::ofstream file(path, std::ios::binary);

    std::visit(
        [&file](const auto &original) {
          file.write(reinterpret_cast<const char *>(original.data()),
                     original.size());
        },
        original);

    const std::byte extra{0x42};

    file.write(reinterpret_cast<const char *>(&extra), 1);
  }

  const auto result = SaltManager::getSaltFromFile(path.string());

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(*result, original);
}
