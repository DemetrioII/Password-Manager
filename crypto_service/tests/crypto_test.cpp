#include "crypto_service/crypto.h"
#include "master_key_generator/masterkey.h"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <string_view>

namespace {

SecureString make_secret(std::string_view value) { return SecureString{value}; }

Key make_key() { return Key{}; }

Key make_wrong_key() {
  Key key;
  key = (*MasterKeyManager::deriveKey(SecureString("secret"),
                                      SaltManager::generateSalt<Argon2Salt>()));
  return key;
}

Nonce make_nonce() { return NonceManager::generate(); }

} // namespace

TEST(CryptoService, EncryptDecryptRoundTrip) {
  auto plaintext = make_secret("super secret password");
  auto key = make_key();
  auto nonce = make_nonce();

  auto ciphertext = CryptoService::cypher(plaintext, nonce, key);

  auto decrypted = CryptoService::decypher(ciphertext, nonce, key);

  EXPECT_EQ(decrypted.view(), plaintext.view());
}

TEST(CryptoService, EncryptionDoesNotModifyPlaintext) {
  auto plaintext = make_secret("super secret password");
  auto key = make_key();
  auto nonce = make_nonce();

  const std::string_view before = plaintext.view();

  [[maybe_unused]]
  auto ciphertext = CryptoService::cypher(plaintext, nonce, key);

  EXPECT_EQ(plaintext.view(), before);
}

TEST(CryptoService, CiphertextHasAuthenticationTag) {
  auto plaintext = make_secret("secret");
  auto key = make_key();
  auto nonce = make_nonce();

  auto ciphertext = CryptoService::cypher(plaintext, nonce, key);

  EXPECT_EQ(ciphertext.size(),
            plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
}

TEST(CryptoService, EncryptionProducesDifferentCiphertextsForDifferentNonces) {
  auto plaintext = make_secret("same secret");
  auto key = make_key();

  auto nonce1 = make_nonce();
  auto nonce2 = make_nonce();

  auto first = CryptoService::cypher(plaintext, nonce1, key);

  auto second = CryptoService::cypher(plaintext, nonce2, key);

  EXPECT_NE(first.view(), second.view());
}

TEST(CryptoService, SameInputsProduceSameCiphertext) {
  auto plaintext = make_secret("same secret");
  auto key = make_key();
  auto nonce = make_nonce();

  auto first = CryptoService::cypher(plaintext, nonce, key);

  auto second = CryptoService::cypher(plaintext, nonce, key);

  EXPECT_EQ(first.view(), second.view());
}

TEST(CryptoService, DifferentPlaintextsProduceDifferentCiphertexts) {
  auto first_plaintext = make_secret("secret one");
  auto second_plaintext = make_secret("secret two");

  auto key = make_key();
  auto nonce = make_nonce();

  auto first = CryptoService::cypher(first_plaintext, nonce, key);

  auto second = CryptoService::cypher(second_plaintext, nonce, key);

  EXPECT_NE(first.view(), second.view());
}

TEST(CryptoService, WrongKeyFailsAuthentication) {
  auto plaintext = make_secret("secret");

  auto key = make_key();
  auto wrong_key = make_wrong_key();

  auto nonce = make_nonce();

  auto ciphertext = CryptoService::cypher(plaintext, nonce, key);

  EXPECT_THROW(CryptoService::decypher(ciphertext, nonce, wrong_key),
               AuthenticationFailed);
}

TEST(CryptoService, WrongNonceFailsAuthentication) {
  auto plaintext = make_secret("secret");

  auto key = make_key();

  auto nonce = make_nonce();
  auto wrong_nonce = make_nonce();

  auto ciphertext = CryptoService::cypher(plaintext, nonce, key);

  EXPECT_THROW(CryptoService::decypher(ciphertext, wrong_nonce, key),
               AuthenticationFailed);
}

TEST(CryptoService, ModifiedCiphertextFailsAuthentication) {
  auto plaintext = make_secret("secret");

  auto key = make_key();
  auto nonce = make_nonce();

  auto ciphertext = CryptoService::cypher(plaintext, nonce, key);

  ASSERT_GT(ciphertext.size(), 0);

  ciphertext.data()[0] ^= 0x01;

  EXPECT_THROW(CryptoService::decypher(ciphertext, nonce, key),
               AuthenticationFailed);
}

TEST(CryptoService, EveryCiphertextByteIsAuthenticated) {
  auto plaintext = make_secret("secret");

  auto key = make_key();
  auto nonce = make_nonce();

  auto ciphertext = CryptoService::cypher(plaintext, nonce, key);

  for (std::size_t i = 0; i < ciphertext.size(); ++i) {
    const auto original = ciphertext.data()[i];

    ciphertext.data()[i] ^= 0x01;

    EXPECT_THROW(CryptoService::decypher(ciphertext, nonce, key),
                 AuthenticationFailed)
        << "Modified byte: " << i;

    ciphertext.data()[i] = original;
  }
}

TEST(CryptoService, TooShortCiphertextIsRejected) {
  auto key = make_key();
  auto nonce = make_nonce();

  SecureString ciphertext{crypto_aead_xchacha20poly1305_ietf_ABYTES - 1};

  EXPECT_THROW(CryptoService::decypher(ciphertext, nonce, key),
               InvalidCiphertext);
}

TEST(CryptoService, AuthenticationTagAloneIsAcceptedAsValidLength) {
  auto key = make_key();
  auto nonce = make_nonce();

  SecureString ciphertext{crypto_aead_xchacha20poly1305_ietf_ABYTES};

  EXPECT_THROW(CryptoService::decypher(ciphertext, nonce, key),
               AuthenticationFailed);
}

TEST(CryptoService, BinaryDataRoundTrip) {
  constexpr std::array<unsigned char, 8> bytes{0x00, 0x01, 0x02, 0x7f,
                                               0x80, 0xfe, 0xff, 0x00};

  SecureString plaintext{
      std::string(reinterpret_cast<const char *>(bytes.data()), bytes.size())};

  auto key = make_key();
  auto nonce = make_nonce();

  auto ciphertext = CryptoService::cypher(plaintext, nonce, key);

  auto decrypted = CryptoService::decypher(ciphertext, nonce, key);

  ASSERT_EQ(decrypted.size(), plaintext.size());

  EXPECT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()),
            0);
}

TEST(CryptoService, UnicodeRoundTrip) {
  auto plaintext = make_secret("пароль 😺 密码 🔐");

  auto key = make_key();
  auto nonce = make_nonce();

  auto ciphertext = CryptoService::cypher(plaintext, nonce, key);

  auto decrypted = CryptoService::decypher(ciphertext, nonce, key);

  EXPECT_EQ(decrypted.view(), plaintext.view());
}

int main(int argc, char **argv) {
  sodium_init();
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
