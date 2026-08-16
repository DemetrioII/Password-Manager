#include "crypto.h"

SecureString CryptoService::cypher(const SecureString &password,
                                   const Nonce &nonce, const Key &key) {
  constexpr std::size_t tag_size = crypto_aead_xchacha20poly1305_ietf_ABYTES;
  SecureString ciphertext{password.size() + tag_size};

  unsigned long long ciphertext_size = 0;

  const int result = crypto_aead_xchacha20poly1305_ietf_encrypt(
      reinterpret_cast<unsigned char *>(ciphertext.data()), &ciphertext_size,
      reinterpret_cast<const unsigned char *>(password.data()), password.size(),
      nullptr, 0, nullptr,
      reinterpret_cast<const unsigned char *>(nonce.data()), key.data());

  if (result != 0)
    throw std::runtime_error("XChaCha20-Poly1305 encryption failed!");

  return ciphertext;
}

SecureString CryptoService::decypher(const SecureString &ciphertext,
                                     const Nonce &nonce, const Key &key) {
  constexpr std::size_t tag_size = crypto_aead_xchacha20poly1305_ietf_ABYTES;
  if (ciphertext.size() < tag_size) {
    throw InvalidCiphertext("ciphertext is too short");
  }

  SecureString password{ciphertext.size() - tag_size};

  unsigned long long plain_text_size = 0;

  int result = crypto_aead_xchacha20poly1305_ietf_decrypt(
      reinterpret_cast<unsigned char *>(password.data()), &plain_text_size,

      nullptr,

      reinterpret_cast<const unsigned char *>(ciphertext.data()),
      ciphertext.size(),

      nullptr, 0, reinterpret_cast<const unsigned char *>(nonce.data()),
      key.data());

  if (result != 0)
    throw AuthenticationFailed("XChaCha20-Poly1305 authentication failed");

  return password;
}
