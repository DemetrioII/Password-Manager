#include "crypto.h"

SecureString CryptoService::cypher(const SecureString &password,
                                   const Nonce &nonce, const Key &key) {
  const std::size_t tag_size = aead_tag_bytes(nonce);
  SecureString ciphertext{password.size() + tag_size};

  unsigned long long ciphertext_size = 0;

  ciphertext.mutate([&](char *out) {
    std::visit(
        [&](const auto &nonce_value) {
          using Params = AeadParams<std::decay_t<decltype(nonce_value)>>;
          const int result = Params::encrypt(
              reinterpret_cast<unsigned char *>(out), &ciphertext_size,
              reinterpret_cast<const unsigned char *>(password.data()),
              password.size(), nullptr, 0, nullptr,
              reinterpret_cast<const unsigned char *>(nonce_value.data()),
              key.data());

          if (result != 0)
            throw CryptoError("Poly1305 AEAD encryption failed!");
        },
        nonce);
  });

  if (ciphertext_size != ciphertext.size())
    throw CryptoError("Poly1305 AEAD encryption produced unexpected size");

  return ciphertext;
}

SecureString CryptoService::decypher(const SecureString &ciphertext,
                                     const Nonce &nonce, const Key &key) {
  const std::size_t tag_size = aead_tag_bytes(nonce);
  if (ciphertext.size() < tag_size) {
    throw InvalidCiphertext("ciphertext is too short");
  }

  SecureString password{ciphertext.size() - tag_size};

  unsigned long long plain_text_size = 0;

  password.mutate([&](char *out) {
    std::visit(
        [&](const auto &nonce_value) {
          using Params = AeadParams<std::decay_t<decltype(nonce_value)>>;
          int result = Params::decrypt(
              reinterpret_cast<unsigned char *>(out), &plain_text_size, nullptr,

              reinterpret_cast<const unsigned char *>(ciphertext.data()),
              ciphertext.size(),

              nullptr, 0, reinterpret_cast<const unsigned char *>(nonce_value.data()),
              key.data());

          if (result != 0)
            throw AuthenticationFailed("Poly1305 AEAD authentication failed");
        },
        nonce);
  });

  if (plain_text_size != password.size())
    throw CryptoError("Unknown error during the decryption");

  return password;
}

std::vector<unsigned char>
CryptoService::encrypt(const char *plaintext, const std::size_t plaintext_size,
                       const std::byte *AAD, const std::size_t AAD_size,
                       const Nonce &nonce, const Key &key) {
  const std::size_t tag_size = aead_tag_bytes(nonce);
  std::vector<unsigned char> ciphertext(plaintext_size + tag_size);

  unsigned long long ciphertext_size = 0;

  std::visit(
      [&ciphertext, &plaintext, &ciphertext_size, &key, &plaintext_size, &AAD,
       &AAD_size](const auto &nonce_value) {
        using Params = AeadParams<std::decay_t<decltype(nonce_value)>>;
        const int result = Params::encrypt(
            reinterpret_cast<unsigned char *>(ciphertext.data()),
            &ciphertext_size,
            reinterpret_cast<const unsigned char *>(plaintext), plaintext_size,
            reinterpret_cast<const unsigned char *>(AAD), AAD_size, nullptr,
            reinterpret_cast<const unsigned char *>(nonce_value.data()),
            key.data());

        if (result != 0)
          throw CryptoError("Poly1305 AEAD encryption failed!");
      },
      nonce);
  return ciphertext;
}

std::string CryptoService::decrypt(const char *ciphertext,
                                   const std::size_t ciphertext_size,
                                   const std::byte *AAD,
                                   const std::size_t AAD_size,
                                   const Nonce &nonce, const Key &key) {
  const std::size_t tag_size = aead_tag_bytes(nonce);
  if (ciphertext_size < tag_size) {
    throw InvalidCiphertext("ciphertext is too short");
  }

  std::string plaintext;
  plaintext.resize(ciphertext_size - tag_size);

  unsigned long long plain_text_size = 0;

  std::visit(
      [&ciphertext, &plain_text_size, &ciphertext_size, &key, &plaintext, &AAD,
       &AAD_size](const auto &nonce_value) {
        using Params = AeadParams<std::decay_t<decltype(nonce_value)>>;
        int result = Params::decrypt(
            reinterpret_cast<unsigned char *>(plaintext.data()),
            &plain_text_size,

            nullptr,

            reinterpret_cast<const unsigned char *>(ciphertext),
            ciphertext_size,

            reinterpret_cast<const unsigned char *>(AAD), AAD_size,
            reinterpret_cast<const unsigned char *>(nonce_value.data()),
            key.data());

        if (result != 0)
          throw AuthenticationFailed("Poly1305 AEAD authentication failed");
      },
      nonce);

  if (plain_text_size != plaintext.size())
    throw CryptoError("Poly1305 AEAD decryption produced unexpected size");

  return plaintext;
}
