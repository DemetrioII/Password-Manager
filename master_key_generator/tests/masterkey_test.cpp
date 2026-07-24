#include "master_key_generator/masterkey.h"
#include <filesystem>
#include <gtest/gtest.h>

TEST(KeyTest, DefaultSize) {
  Key key;

  EXPECT_EQ(key.size(), crypto_aead_xchacha20poly1305_IETF_KEYBYTES);
}

TEST(KeyTest, MoveConstructor) {
  Key key;

  randombytes_buf(key.data(), key.size());

  std::vector<unsigned char> before(key.data(), key.data() + key.size());

  Key moved(std::move(key));

  EXPECT_TRUE(std::equal(before.begin(), before.end(), moved.data()));
}

TEST(KeyTest, MoveAssignment) {
  Key a;
  Key b;

  randombytes_buf(a.data(), a.size());

  std::vector<unsigned char> before(a.data(), a.data() + a.size());

  b = std::move(a);

  EXPECT_TRUE(std::equal(before.begin(), before.end(), b.data()));
}

TEST(KeyTest, Equal) {
  Key a;
  Key b;

  randombytes_buf(a.data(), a.size());

  std::copy(a.data(), a.data() + a.size(), b.data());

  EXPECT_EQ(a, b);
}

TEST(KeyTest, NotEqual) {
  Key a;
  Key b;

  randombytes_buf(a.data(), a.size());
  randombytes_buf(b.data(), b.size());

  EXPECT_NE(a, b);
}

TEST(SaltManagerTest, GenerateSalt) {
  Salt s1 = SaltManager::generateSalt();
  Salt s2 = SaltManager::generateSalt();

  EXPECT_EQ(s1.size(), crypto_pwhash_SALTBYTES);

  EXPECT_NE(memcmp(s1.data(), s2.data(), s1.size()), 0);
}

TEST(SaltManagerTest, SaveAndLoad) {
  auto salt = SaltManager::generateSalt();

  SaltManager::saveToFile(salt, "salt.bin");

  auto loaded = SaltManager::getSaltFromFile("salt.bin");

  ASSERT_TRUE(loaded.has_value());

  EXPECT_EQ(memcmp(salt.data(), loaded->data(), salt.size()), 0);

  std::filesystem::remove("salt.bin");
}

TEST(SaltManagerTest, MissingFile) {
  auto result = SaltManager::getSaltFromFile("does_not_exist.bin");

  EXPECT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), KeyManagerError::FileNotFound);
}

TEST(NonceManagerTest, SaveAndLoad) {
  auto nonce = NonceManager::generate();

  NonceManager::write_to_file("nonce.bin", nonce);

  auto loaded = NonceManager::read_from_file("nonce.bin");

  ASSERT_TRUE(loaded.has_value());

  EXPECT_EQ(memcmp(nonce.data(), loaded->data(), nonce.size()), 0);

  std::filesystem::remove("nonce.bin");
}

TEST(NonceManagerTest, GenerateNonce) {
  auto n1 = NonceManager::generate();
  auto n2 = NonceManager::generate();

  EXPECT_NE(memcmp(n1.data(), n2.data(), n1.size()), 0);
}

TEST(MasterKeyManagerTest, SamePasswordSameSalt) {
  auto salt = SaltManager::generateSalt();

  auto k1 = MasterKeyManager::deriveKey("password", salt);

  auto k2 = MasterKeyManager::deriveKey("password", salt);

  ASSERT_TRUE(k1);
  ASSERT_TRUE(k2);

  EXPECT_EQ(*k1, *k2);
}

TEST(MasterKeyManagerTest, DifferentPasswords) {
  auto salt = SaltManager::generateSalt();

  auto k1 = MasterKeyManager::deriveKey("abc", salt);

  auto k2 = MasterKeyManager::deriveKey("xyz", salt);

  ASSERT_TRUE(k1);
  ASSERT_TRUE(k2);

  EXPECT_NE(*k1, *k2);
}

TEST(MasterKeyManagerTest, DifferentSalts) {
  auto s1 = SaltManager::generateSalt();
  auto s2 = SaltManager::generateSalt();

  auto k1 = MasterKeyManager::deriveKey("password", s1);

  auto k2 = MasterKeyManager::deriveKey("password", s2);

  ASSERT_TRUE(k1);
  ASSERT_TRUE(k2);

  EXPECT_NE(*k1, *k2);
}
