#include "master_key_generator/encryptedfield.h"
#include "master_key_generator/utils.h"

SecureString EncryptedField::decrypt(const EphemeralKey &session_key) const {
  constexpr std::size_t tag_size = crypto_aead_xchacha20poly1305_ietf_ABYTES;
  if (ciphertext.size() < tag_size) {
    throw InvalidCiphertext("Ciphertext is too short");
  }

  SecureString plain_text{ciphertext.size() - tag_size};

  unsigned long long plain_text_size = 0;

  std::visit(
      [&plain_text, &session_key, this, &plain_text_size](const auto &nonce) {
        const int result = crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char *>(plain_text.data()),
            &plain_text_size,

            nullptr,

            ciphertext.data(), ciphertext.size(),

            nullptr, 0,

            reinterpret_cast<const unsigned char *>(nonce.data()),
            session_key.data());

        if (result != 0)
          throw AuthenticationFailed(
              "XChaCha20-Poly1305 authentication failed");
      },
      nonce);

  if (plain_text_size != plain_text.size())
    throw CryptoError("Unknown error during the decryption");
  return plain_text;
}

EncryptedField EncryptedField::encrypt(const SecureString &plain_text,
                                       const EphemeralKey &session_key) {
  EncryptedField field;
  field.nonce = NonceManager::generate<XChaCha20Poly1305Nonce>();
  field.ciphertext.resize(plain_text.size() +
                          crypto_aead_xchacha20poly1305_ietf_ABYTES);

  unsigned long long ciphertext_size = 0;

  std::visit(
      [&field, &plain_text, &session_key, &ciphertext_size](const auto &value) {
        const int result = crypto_aead_xchacha20poly1305_ietf_encrypt(
            field.ciphertext.data(), &ciphertext_size,

            reinterpret_cast<const unsigned char *>(plain_text.data()),
            plain_text.size(),

            nullptr, 0,

            nullptr,

            reinterpret_cast<const unsigned char *>(value.data()),
            session_key.data());

        if (result != 0)
          throw CryptoError("XChaCha20-Poly1305 encryption failed");
      },
      field.nonce);

  field.ciphertext.resize(ciphertext_size);
  return field;
}
