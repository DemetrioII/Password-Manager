#include "master_key_generator/encryptedfield.h"
#include "master_key_generator/utils.h"

SecureString EncryptedField::decrypt(const EphemeralKey &session_key) const {
  const std::size_t tag_size = aead_tag_bytes(nonce);
  if (ciphertext.size() < tag_size) {
    throw InvalidCiphertext("Ciphertext is too short");
  }

  SecureString plain_text{ciphertext.size() - tag_size};

  unsigned long long plain_text_size = 0;

  plain_text.mutate([&](char *out) {
    std::visit(
        [&](const auto &nonce_value) {
          using Params = AeadParams<std::decay_t<decltype(nonce_value)>>;
          const int result = Params::decrypt(
              reinterpret_cast<unsigned char *>(out), &plain_text_size, nullptr,

              ciphertext.data(), ciphertext.size(), nullptr, 0,

              reinterpret_cast<const unsigned char *>(nonce_value.data()),
              session_key.data());

          if (result != 0)
            throw AuthenticationFailed("Poly1305 AEAD authentication failed");
        },
        nonce);
  });

  if (plain_text_size != plain_text.size())
    throw CryptoError("Unknown error during the decryption");
  return plain_text;
}

EncryptedField EncryptedField::encrypt(const SecureString &plain_text,
                                       const EphemeralKey &session_key) {
  EncryptedField field;
  // Session fields are deliberately kept on XChaCha20: their nonce is not part
  // of the vault-cipher negotiation and never leaves memory.
  field.nonce = NonceManager::generate<XChaCha20Poly1305Nonce>();
  field.ciphertext.resize(plain_text.size() + aead_tag_bytes(field.nonce));

  unsigned long long ciphertext_size = 0;

  std::visit(
      [&field, &plain_text, &session_key, &ciphertext_size](const auto &value) {
        using Params = AeadParams<std::decay_t<decltype(value)>>;
        const int result = Params::encrypt(
            field.ciphertext.data(), &ciphertext_size,

            reinterpret_cast<const unsigned char *>(plain_text.data()),
            plain_text.size(),

            nullptr, 0,

            nullptr,

            reinterpret_cast<const unsigned char *>(value.data()),
            session_key.data());

        if (result != 0)
          throw CryptoError("Poly1305 AEAD encryption failed");
      },
      field.nonce);

  field.ciphertext.resize(ciphertext_size);
  return field;
}
