#include "crypto.h"

SecureString CryptoService::cypher(const SecureString &password,
                                   const Nonce &nonce, const Key &key) {
  constexpr std::size_t tag_size = crypto_aead_xchacha20poly1305_ietf_ABYTES;
  SecureString ciphertext{password.size() + tag_size};

  unsigned long long ciphertext_size = 0;

  std::visit(
      [&ciphertext, &password, &ciphertext_size, &key](const auto &nonce) {
        const int result = crypto_aead_xchacha20poly1305_ietf_encrypt(
            reinterpret_cast<unsigned char *>(ciphertext.data()),
            &ciphertext_size,
            reinterpret_cast<const unsigned char *>(password.data()),
            password.size(), nullptr, 0, nullptr,
            reinterpret_cast<const unsigned char *>(nonce.data()), key.data());

        if (result != 0)
          throw std::runtime_error("XChaCha20-Poly1305 encryption failed!");
      },
      nonce);
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

  std::visit(
      [&password, &plain_text_size, &ciphertext, &key](const auto &nonce) {
        int result = crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char *>(password.data()),
            &plain_text_size,

            nullptr,

            reinterpret_cast<const unsigned char *>(ciphertext.data()),
            ciphertext.size(),

            nullptr, 0, reinterpret_cast<const unsigned char *>(nonce.data()),
            key.data());

        if (result != 0)
          throw AuthenticationFailed(
              "XChaCha20-Poly1305 authentication failed");
      },
      nonce);
  return password;
}

std::vector<unsigned char>
CryptoService::encrypt(const char *plaintext, const std::size_t plaintext_size,
                       const std::byte *AAD, const std::size_t AAD_size,
                       const Nonce &nonce, const Key &key) {
  constexpr std::size_t tag_size = crypto_aead_xchacha20poly1305_ietf_ABYTES;
  std::vector<unsigned char> ciphertext(plaintext_size + tag_size);

  unsigned long long ciphertext_size = 0;

  std::visit(
      [&ciphertext, &plaintext, &ciphertext_size, &key, &plaintext_size, &AAD,
       &AAD_size](const auto &nonce) {
        const int result = crypto_aead_xchacha20poly1305_ietf_encrypt(
            reinterpret_cast<unsigned char *>(ciphertext.data()),
            &ciphertext_size,
            reinterpret_cast<const unsigned char *>(plaintext), plaintext_size,
            reinterpret_cast<const unsigned char *>(AAD), AAD_size, nullptr,
            reinterpret_cast<const unsigned char *>(nonce.data()), key.data());

        if (result != 0)
          throw std::runtime_error("XChaCha20-Poly1305 encryption failed!");
      },
      nonce);
  return ciphertext;
}

std::string CryptoService::decrypt(const char *ciphertext,
                                   const std::size_t ciphertext_size,
                                   const std::byte *AAD,
                                   const std::size_t AAD_size,
                                   const Nonce &nonce, const Key &key) {
  constexpr std::size_t tag_size = crypto_aead_xchacha20poly1305_ietf_ABYTES;
  if (ciphertext_size < tag_size) {
    throw InvalidCiphertext("ciphertext is too short");
  }

  std::string plaintext;
  plaintext.resize(ciphertext_size - tag_size);

  unsigned long long plain_text_size = 0;

  std::visit(
      [&ciphertext, &plain_text_size, &ciphertext_size, &key, &plaintext, &AAD,
       &AAD_size](const auto &nonce) {
        int result = crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char *>(plaintext.data()),
            &plain_text_size,

            nullptr,

            reinterpret_cast<const unsigned char *>(ciphertext),
            ciphertext_size,

            reinterpret_cast<const unsigned char *>(AAD), AAD_size,
            reinterpret_cast<const unsigned char *>(nonce.data()), key.data());

        if (result != 0)
          throw AuthenticationFailed(
              "XChaCha20-Poly1305 authentication failed");
      },
      nonce);
  return plaintext;
}
