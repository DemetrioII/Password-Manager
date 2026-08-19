#pragma once
#include "master_key_generator/encryptedfield.h"
#include "master_key_generator/ephemeralkey.h"
#include "master_key_generator/masterkey.h"
#include <exception>
#include <iostream>
#include <sodium.h>
#include <string>
#include <vector>

class CryptoService {
public:
  static SecureString cypher(const SecureString &password, const Nonce &nonce,
                             const Key &key);

  static SecureString decypher(const SecureString &password, const Nonce &nonce,
                               const Key &key);

  static std::vector<unsigned char> encrypt(const char *plaintext,
                                            const std::size_t plaintext_size,
                                            const std::byte *AAD,
                                            const std::size_t AAD_size,
                                            const Nonce &nonce, const Key &key);

  static std::string decrypt(const char *ciphertext,
                             const std::size_t ciphertext_size,
                             const std::byte *AAD, const std::size_t AAD_size,
                             const Nonce &nonce, const Key &key);
};
