#include "crypto_service/crypto.h"
#include <gtest/gtest.h>

class CryptoTest : public ::testing::Test {
protected:
  void SetUp() override {
    salt = SaltManager::generateSalt();
    key = *MasterKeyManager::deriveKey("master", salt);
    nonce = NonceManager::generate();
  }

  Key key;
  Salt salt;
  Nonce nonce;
};

TEST_F(CryptoTest, CorruptedCiphertextFails) {
  std::string plaintext = "password123";

  auto ciphertext = CryptoService::cypher(plaintext, nonce, key);

  ciphertext[0] ^= 0xFF;

  EXPECT_THROW(CryptoService::decypher(ciphertext, nonce, key),
               std::runtime_error);
}

TEST_F(CryptoTest, DifferentNoncesProduceDifferentCiphertexts) {
  std::string plaintext = "same password";

  Nonce nonce2 = NonceManager::generate();

  auto cipher1 = CryptoService::cypher(plaintext, nonce, key);

  auto cipher2 = CryptoService::cypher(plaintext, nonce2, key);

  EXPECT_NE(cipher1, cipher2);
}

TEST_F(CryptoTest, WrongKeyFailsDecryption) {
  std::string plaintext = "secret";

  auto ciphertext = CryptoService::cypher(plaintext, nonce, key);

  Key wrong_key = *MasterKeyManager::deriveKey("wrong master", salt);

  EXPECT_THROW(CryptoService::decypher(ciphertext, nonce, wrong_key),
               std::runtime_error);

  Salt other_salt = SaltManager::generateSalt();

  wrong_key = *MasterKeyManager::deriveKey("master", other_salt);

  EXPECT_THROW(CryptoService::decypher(ciphertext, nonce, wrong_key),
               std::runtime_error);
}

TEST_F(CryptoTest, EmptyString) {
  std::string plaintext = "";
  auto ciphertext = CryptoService::cypher(plaintext, nonce, key);
  auto decrypted = CryptoService::decypher(ciphertext, nonce, key);
  EXPECT_TRUE(decrypted.empty());
}

int main() {
  sodium_init();
  ::testing::InitGoogleTest();
  return RUN_ALL_TESTS();
}
