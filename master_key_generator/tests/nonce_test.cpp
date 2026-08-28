#include "master_key_generator/utils.h"

#include <gtest/gtest.h>

#include <array>
#include <filesystem>
#include <fstream>

namespace {

class NonceTest : public ::testing::Test {
protected:
  std::filesystem::path path =
      std::filesystem::temp_directory_path() / "password_manager_nonce_test";

  void TearDown() override { std::filesystem::remove(path); }
};

} // namespace

TEST_F(NonceTest, GenerateHasCorrectSize) {
  const auto nonce = NonceManager::generate();

  std::visit(
      [](const auto &nonce) {
        EXPECT_EQ(nonce.size(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
      },
      nonce);
}

TEST_F(NonceTest, GeneratedNonceIsNotAllZeroes) {
  const auto nonce = NonceManager::generate();

  std::visit(
      [](const auto &nonce) {
        const bool all_zero =
            std::all_of(nonce.begin(), nonce.end(),
                        [](std::byte value) { return value == std::byte{0}; });

        EXPECT_FALSE(all_zero);
      },
      nonce);
}

TEST_F(NonceTest, TwoGeneratedNoncesAreDifferent) {
  const auto first = NonceManager::generate();
  const auto second = NonceManager::generate();

  EXPECT_NE(first, second);
}

TEST_F(NonceTest, WriteThenReadReturnsSameNonce) {
  const auto original = NonceManager::generate();

  NonceManager::write_to_file(path.string(), original);

  const auto result = NonceManager::read_from_file(path.string());

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(*result, original);
}

TEST_F(NonceTest, MissingFileReturnsError) {
  const auto result = NonceManager::read_from_file(path.string());

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), KeyManagerError::FileNotFound);
}

TEST_F(NonceTest, TruncatedFileReturnsError) {
  {
    std::ofstream file(path, std::ios::binary);

    const std::array<std::byte, 4> garbage{};
    file.write(reinterpret_cast<const char *>(garbage.data()), garbage.size());
  }

  const auto result = NonceManager::read_from_file(path.string());

  EXPECT_FALSE(result.has_value());
}

TEST_F(NonceTest, EmptyFileReturnsError) {
  {
    std::ofstream file(path, std::ios::binary);
  }

  const auto result = NonceManager::read_from_file(path.string());

  EXPECT_FALSE(result.has_value());
}

TEST_F(NonceTest, ExtraBytesAreIgnored) {
  const auto original = NonceManager::generate();

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

  const auto result = NonceManager::read_from_file(path.string());

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(*result, original);
}
