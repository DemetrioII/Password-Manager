#include "crypto.h"

SecureString CryptoService::cypher(const SecureString &password, Nonce &nonce,
                                   const Key &key) {
  SecureString ciphertext{
      std::string(password.size() + crypto_secretbox_MACBYTES, '\0')};

  if (crypto_secretbox_easy(
          reinterpret_cast<unsigned char *>(ciphertext.data()),
          reinterpret_cast<const unsigned char *>(password.data()),
          password.size(),
          reinterpret_cast<const unsigned char *>(nonce.data()),
          reinterpret_cast<const unsigned char *>(key.data())) != 0) {
    throw std::runtime_error("encryption failed");
  }

  return ciphertext;
}

SecureString CryptoService::decypher(const SecureString &ciphertext,
                                     Nonce &nonce, const Key &key) {
  if (ciphertext.size() < crypto_secretbox_MACBYTES) {
    throw std::runtime_error("ciphertext is too short");
  }

  SecureString password{
      std::string(ciphertext.size() - crypto_secretbox_MACBYTES, '\0')};

  if (crypto_secretbox_open_easy(
          reinterpret_cast<unsigned char *>(password.data()),
          reinterpret_cast<const unsigned char *>(ciphertext.data()),
          ciphertext.size(),
          reinterpret_cast<const unsigned char *>(nonce.data()),
          reinterpret_cast<const unsigned char *>(key.data())) != 0) {
    throw std::runtime_error("error during decoding");
  }

  return password;
}
