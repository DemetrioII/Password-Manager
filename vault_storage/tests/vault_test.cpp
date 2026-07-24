#include "vault_storage/vault.h"
#include <gtest/gtest.h>

class VaultTest : public ::testing::Test {
protected:
  vault::Vault vault;
  PasswordEntry entry;
  VaultKeys keys;
  Salt master_salt, meta_salt;
  Nonce vault_nonce;

  std::string vault_file = "vault.bin";

  void SetUp() override {
    sodium_init();
    entry.id = "0";
    entry.login = "login";
    Nonce nonce = NonceManager::generate();
    entry.nonce = nonce;
    entry.notes = "";
    entry.title = "";

    master_salt = SaltManager::generateSalt();
    meta_salt = SaltManager::generateSalt();
    SaltManager::saveToFile(master_salt, "mastersalt.bin");
    SaltManager::saveToFile(meta_salt, "metasalt.bin");
    keys = vault::derive_keys_from_password("master_password", meta_salt,
                                            master_salt);
    vault_nonce = NonceManager::generate();
    vault.unlock();
    NonceManager::write_to_file("vault.nonce", vault_nonce);
  }

  void TearDown() override {}
};

TEST_F(VaultTest, EmptyVaultSerialization) {
  vault::Vault vault;
  vault.set_key(std::move(keys));

  EXPECT_TRUE(vault::Serializator::serialize(vault_file, vault, "vault.nonce")
                  .has_value());

  auto deserialize_res =
      vault::Serializator::deserialize(vault_file, vault, "vault.nonce");

  EXPECT_TRUE(deserialize_res.has_value());

  EXPECT_TRUE(vault.Entries().empty());
}

TEST_F(VaultTest, SerializeDeserializeOneEntry) {
  vault::Vault vault;
  vault.set_key(std::move(keys));
  EXPECT_TRUE(vault.unlock().has_value());
  EXPECT_TRUE(vault.Add(entry).has_value());

  EXPECT_TRUE(vault::Serializator::serialize(vault_file, vault, "vault.nonce")
                  .has_value());

  EXPECT_TRUE(vault::Serializator::deserialize(vault_file, vault, "vault.nonce")
                  .has_value());

  ASSERT_EQ(vault.Entries().size(), 1);

  const auto &e = vault.Entries()[0];

  EXPECT_EQ(e.id, entry.id);
  EXPECT_EQ(e.title, entry.title);
  EXPECT_EQ(e.login, entry.login);
  EXPECT_EQ(e.password, entry.password);
  EXPECT_EQ(e.notes, entry.notes);
}

TEST_F(VaultTest, RemoveEntry) {
  vault::Vault vault;
  EXPECT_TRUE(vault.unlock().has_value());
  EXPECT_TRUE(vault.Add(entry).has_value());

  PasswordEntry second = entry;
  second.id = "2";

  EXPECT_TRUE(vault.Add(second).has_value());

  EXPECT_TRUE(vault.Remove(0).has_value());

  ASSERT_EQ(vault.Entries().size(), 1);
  EXPECT_EQ(vault.Entries()[0].id, "2");
}

TEST_F(VaultTest, WrongKeyThrows) {
  vault::Vault vault;
  vault.set_key(std::move(keys));
  EXPECT_TRUE(vault.unlock().has_value());
  EXPECT_TRUE(vault.Add(entry).has_value());

  EXPECT_TRUE(vault::Serializator::serialize(vault_file, vault, "vault.nonce")
                  .has_value());

  vault::Vault restored;

  VaultKeys wrongKey;
  randombytes_buf(wrongKey.master_key.data(), wrongKey.master_key.size());
  randombytes_buf(wrongKey.meta_key.data(), wrongKey.meta_key.size());

  restored.set_key(std::move(wrongKey));
}

TEST_F(VaultTest, MissingVaultFile) {
  vault::Vault vault;
  vault.set_key(std::move(keys));
}

int main() {
  ::testing::InitGoogleTest();
  RUN_ALL_TESTS();
  return 0;
}
