#include "master_key_generator/encryptedfield.h"
#include "master_key_generator/utils.h"

SecureString EncryptedField::decrypt(const EphemeralKey &session_key) const {
  constexpr std::size_t tag_size = crypto_aead_xchacha20poly1305_ietf_ABYTES;
  if (ciphertext.size() < tag_size) {
    throw InvalidCiphertext("Ciphertext is too short");
  }

  SecureString plain_text{ciphertext.size() - tag_size};

  unsigned long long plain_text_size = 0;

  const int result = crypto_aead_xchacha20poly1305_ietf_decrypt(
      reinterpret_cast<unsigned char *>(plain_text.data()), &plain_text_size,

      nullptr,

      ciphertext.data(), ciphertext.size(),

      nullptr, 0,

      reinterpret_cast<const unsigned char *>(nonce.data()),
      session_key.data());

  if (result != 0)
    throw AuthenticationFailed("XChaCha20-Poly1305 authentication failed");

  return plain_text;
}

EncryptedField EncryptedField::encrypt(std::string_view plain_text,
                                       const EphemeralKey &session_key) {
  EncryptedField field;
  field.nonce = NonceManager::generate();
  field.ciphertext.resize(plain_text.size() +
                          crypto_aead_xchacha20poly1305_ietf_ABYTES);

  unsigned long long ciphertext_size = 0;

  const int result = crypto_aead_xchacha20poly1305_ietf_encrypt(
      field.ciphertext.data(), &ciphertext_size,

      reinterpret_cast<const unsigned char *>(plain_text.data()),
      plain_text.size(),

      nullptr, 0,

      nullptr,

      reinterpret_cast<const unsigned char *>(field.nonce.data()),
      session_key.data());

  if (result != 0)
    throw CryptoError("XChaCha20-Poly1305 encryption failed");

  field.ciphertext.resize(ciphertext_size);
  return field;
}
