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

Nonce make_chacha_nonce() {
  return NonceManager::generate<ChaCha20Poly1305Nonce>();
}

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

  ASSERT_GT(ciphertext.size(), 0u);

  std::string corrupted{ciphertext.view()};
  corrupted[0] ^= 0x01;

  EXPECT_THROW(CryptoService::decypher(SecureString{corrupted}, nonce, key),
               AuthenticationFailed);
}

TEST(CryptoService, EveryCiphertextByteIsAuthenticated) {
  auto plaintext = make_secret("secret");

  auto key = make_key();
  auto nonce = make_nonce();

  auto ciphertext = CryptoService::cypher(plaintext, nonce, key);

  std::string clean{ciphertext.view()};

  for (std::size_t i = 0; i < ciphertext.size(); ++i) {
    std::string corrupted = clean;
    corrupted[i] ^= 0x01;

    EXPECT_THROW(CryptoService::decypher(SecureString{corrupted}, nonce, key),
                 AuthenticationFailed)
        << "Modified byte: " << i;
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

TEST(CryptoService, VectorEncryptDecryptRoundTrip) {
  auto key = make_key();
  auto nonce = make_nonce();

  const std::string plaintext = "super secret password";
  const std::string aad = "vault-header";

  const auto *aad_bytes = reinterpret_cast<const std::byte *>(aad.data());

  auto ciphertext =
      CryptoService::encrypt(plaintext.data(), plaintext.size(), aad_bytes,
                             aad.size(), nonce, key);

  EXPECT_EQ(ciphertext.size(),
            plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);

  auto decrypted = CryptoService::decrypt(
      reinterpret_cast<const char *>(ciphertext.data()), ciphertext.size(),
      aad_bytes, aad.size(), nonce, key);

  EXPECT_EQ(decrypted, plaintext);
}

TEST(CryptoService, VectorDecryptWrongAadFailsAuthentication) {
  auto key = make_key();
  auto nonce = make_nonce();

  const std::string plaintext = "super secret password";
  const std::string aad = "vault-header";
  const std::string wrong_aad = "vault-headeR";

  const auto *aad_bytes = reinterpret_cast<const std::byte *>(aad.data());
  const auto *wrong_aad_bytes =
      reinterpret_cast<const std::byte *>(wrong_aad.data());

  auto ciphertext =
      CryptoService::encrypt(plaintext.data(), plaintext.size(), aad_bytes,
                             aad.size(), nonce, key);

  EXPECT_THROW(CryptoService::decrypt(
                   reinterpret_cast<const char *>(ciphertext.data()),
                   ciphertext.size(), wrong_aad_bytes, wrong_aad.size(), nonce,
                   key),
               AuthenticationFailed);
}

TEST(CryptoService, VectorDecryptTooShortCiphertextIsRejected) {
  auto key = make_key();
  auto nonce = make_nonce();

  std::array<char, crypto_aead_xchacha20poly1305_ietf_ABYTES - 1> ciphertext{};

  EXPECT_THROW(CryptoService::decrypt(ciphertext.data(), ciphertext.size(),
                                      nullptr, 0, nonce, key),
               InvalidCiphertext);
}

TEST(CryptoService, ChaCha20Poly1305RoundTrip) {
  auto plaintext = make_secret("super secret password");
  auto key = make_key();
  auto nonce = make_chacha_nonce();

  auto ciphertext = CryptoService::cypher(plaintext, nonce, key);

  EXPECT_EQ(ciphertext.size(),
            plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);

  auto decrypted = CryptoService::decypher(ciphertext, nonce, key);

  EXPECT_EQ(decrypted.view(), plaintext.view());
}

TEST(CryptoService, ChaCha20Poly1305WrongNonceFailsAuthentication) {
  auto plaintext = make_secret("secret");
  auto key = make_key();
  auto nonce = make_chacha_nonce();
  auto wrong_nonce = make_chacha_nonce();

  auto ciphertext = CryptoService::cypher(plaintext, nonce, key);

  EXPECT_THROW(CryptoService::decypher(ciphertext, wrong_nonce, key),
               AuthenticationFailed);
}

TEST(CryptoService, ChaCha20Poly1305VectorRoundTripWithAad) {
  auto key = make_key();
  auto nonce = make_chacha_nonce();

  const std::string plaintext = "super secret password";
  const std::string aad = "vault-header";

  const auto *aad_bytes = reinterpret_cast<const std::byte *>(aad.data());

  auto ciphertext =
      CryptoService::encrypt(plaintext.data(), plaintext.size(), aad_bytes,
                             aad.size(), nonce, key);

  EXPECT_EQ(ciphertext.size(),
            plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);

  auto decrypted = CryptoService::decrypt(
      reinterpret_cast<const char *>(ciphertext.data()), ciphertext.size(),
      aad_bytes, aad.size(), nonce, key);

  EXPECT_EQ(decrypted, plaintext);
}

TEST(CryptoService, ChaCha20Poly1305VectorWrongAadFailsAuthentication) {
  auto key = make_key();
  auto nonce = make_chacha_nonce();

  const std::string plaintext = "super secret password";
  const std::string aad = "vault-header";
  const std::string wrong_aad = "vault-headeR";

  const auto *aad_bytes = reinterpret_cast<const std::byte *>(aad.data());
  const auto *wrong_aad_bytes =
      reinterpret_cast<const std::byte *>(wrong_aad.data());

  auto ciphertext =
      CryptoService::encrypt(plaintext.data(), plaintext.size(), aad_bytes,
                             aad.size(), nonce, key);

  EXPECT_THROW(CryptoService::decrypt(
                   reinterpret_cast<const char *>(ciphertext.data()),
                   ciphertext.size(), wrong_aad_bytes, wrong_aad.size(), nonce,
                   key),
               AuthenticationFailed);
}

int main(int argc, char **argv) {
  if (sodium_init() < 0)
    return 1;
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
