#pragma once
#include "master_key_generator/masterkey.h"
#include <exception>
#include <iostream>
#include <sodium.h>
#include <string>
#include <vector>

#define KEY_LEN crypto_box_SEEDBYTES

enum class CryptoError {

};

class CryptoService {
public:
  static SecureString cypher(const SecureString &password, Nonce &nonce,
                             const Key &key);

  static SecureString decypher(const SecureString &password, Nonce &nonce,
                               const Key &key);
};
