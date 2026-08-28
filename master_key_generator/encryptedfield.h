#pragma once
#include "master_key_generator/ephemeralkey.h"
#include "master_key_generator/securestring.h"
#include "utils.h"
#include <sodium.h>
#include <vector>

struct EncryptedField {
  std::vector<unsigned char> ciphertext;
  Nonce nonce;

  SecureString decrypt(const EphemeralKey &session_key) const;

  static EncryptedField encrypt(const SecureString &plain_text,
                                const EphemeralKey &session_key);
};
