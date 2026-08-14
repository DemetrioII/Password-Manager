#include "master_key_generator/encryptedfield.h"
#include "master_key_generator/utils.h"

SecureString EncryptedField::decrypt(const EphemeralKey &session_key) const {
  if (ciphertext.size() < crypto_secretbox_MACBYTES) {
    throw std::runtime_error("Invalid ciphertext");
  }

  SecureString plain_text{ciphertext.size() - crypto_secretbox_MACBYTES};

  if (crypto_secretbox_open_easy(
          reinterpret_cast<unsigned char *>(plain_text.data()),
          ciphertext.data(), ciphertext.size(),
          reinterpret_cast<const unsigned char *>(nonce.data()),
          session_key.data()) != 0) {
    throw std::runtime_error("RAM Decryption failed! Memory corruption!");
  }

  return plain_text;
}

EncryptedField EncryptedField::encrypt(std::string_view plain_text,
                                       const EphemeralKey &session_key) {
  EncryptedField field;
  field.nonce = NonceManager::generate();
  field.ciphertext.resize(plain_text.size() + crypto_secretbox_MACBYTES);

  crypto_secretbox_easy(
      field.ciphertext.data(),
      reinterpret_cast<const unsigned char *>(plain_text.data()),
      plain_text.size(),
      reinterpret_cast<const unsigned char *>(field.nonce.data()),
      session_key.data());

  return field;
}
