#include "vault_storage/vault.h"
#include <gtest/gtest.h>

class VaultTest : public ::testing::Test {
protected:
  Vault vault;
  PasswordEntry entry;

  void SetUp() override {
    entry.id = "0";
    entry.login = "login";
    Nonce nonce = NonceManager::generate();
    entry.nonce =
        std::string(reinterpret_cast<const char *>(nonce.data()), nonce.size());
    entry.notes = "";
    entry.title = "";
  }

  void TearDown() override {}
};

TEST_F(VaultTest, BasicTest) {
  Vault vault;
  vault.Add(entry);
  Serializator serializator;
  serializator.serialize("vault.bin", vault);
}
