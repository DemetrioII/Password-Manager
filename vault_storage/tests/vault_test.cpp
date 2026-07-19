#include "vault_storage/vault.h"
#include <gtest/gtest.h>

class VaultTest : public ::testing::Test {
protected:
  Vault vault;
  PasswordEntry entry;
  Key key;
  Salt salt;
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

    salt = SaltManager::generateSalt();
    SaltManager::saveToFile(salt, "salt.bin");
    key = *MasterKeyManager::deriveKey("master_password", salt);
    vault_nonce = NonceManager::generate();
    NonceManager::write_to_file("vault.nonce", vault_nonce);
  }

  void TearDown() override {}
};

TEST_F(VaultTest, EmptyVaultSerialization) {
  Vault vault;
  vault.set_key(key);

  EXPECT_TRUE(
      Serializator::serialize(vault_file, vault, "vault.nonce").has_value());

  Vault restored;
  restored.set_key(key);

  auto deserialize_res =
      Serializator::deserialize(vault_file, restored, "vault.nonce");

  EXPECT_TRUE(deserialize_res.has_value());

  EXPECT_TRUE(restored.Entries().empty());
}

TEST_F(VaultTest, SerializeDeserializeOneEntry) {
  Vault vault;
  vault.set_key(key);

  vault.Add(entry);

  EXPECT_TRUE(
      Serializator::serialize(vault_file, vault, "vault.nonce").has_value());

  Vault restored;
  restored.set_key(key);

  EXPECT_TRUE(Serializator::deserialize(vault_file, restored, "vault.nonce")
                  .has_value());

  ASSERT_EQ(restored.Entries().size(), 1);

  const auto &e = restored.Entries()[0];

  EXPECT_EQ(e.id, entry.id);
  EXPECT_EQ(e.title, entry.title);
  EXPECT_EQ(e.login, entry.login);
  EXPECT_EQ(e.password, entry.password);
  EXPECT_EQ(e.notes, entry.notes);
}

TEST_F(VaultTest, RemoveEntry) {
  Vault vault;

  vault.Add(entry);

  PasswordEntry second = entry;
  second.id = "2";

  vault.Add(second);

  vault.Remove(0);

  ASSERT_EQ(vault.Entries().size(), 1);
  EXPECT_EQ(vault.Entries()[0].id, "2");
}

TEST_F(VaultTest, WrongKeyThrows) {
  Vault vault;
  vault.set_key(key);

  vault.Add(entry);

  EXPECT_TRUE(
      Serializator::serialize(vault_file, vault, "vault.nonce").has_value());

  Vault restored;

  Key wrongKey;
  randombytes_buf(wrongKey.data(), wrongKey.size());

  restored.set_key(wrongKey);
}

TEST_F(VaultTest, MissingVaultFile) {
  Vault vault;
  vault.set_key(key);
}

int main() {
  ::testing::InitGoogleTest();
  RUN_ALL_TESTS();
  return 0;
}
