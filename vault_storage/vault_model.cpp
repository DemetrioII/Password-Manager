#include "vault_storage/vault_model.hpp"

vault::VaultKeys vault::derive_keys_from_password(
    SecureString &&password,
    const std::array<std::byte, crypto_pwhash_SALTBYTES> &salt_meta,
    const std::array<std::byte, crypto_pwhash_SALTBYTES> &salt_pass) {
  VaultKeys keys;

  if (crypto_pwhash(keys.meta_key.data(), keys.meta_key.size(), password.data(),
                    password.size(),
                    reinterpret_cast<const unsigned char *>(salt_meta.data()),
                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_ARGON2ID13) != 0) {
    throw KDFError("Out of memory during Argon2id");
  }

  if (crypto_pwhash(keys.master_key.data(), keys.master_key.size(),
                    password.data(), password.size(),
                    reinterpret_cast<const unsigned char *>(salt_pass.data()),
                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_ARGON2ID13) != 0) {
    throw KDFError("Out of memory during Argon2id");
  }

  return keys;
}

vault::VaultHeader vault::make_header(const Salt &meta_salt,
                                      const Salt &master_salt,
                                      const Nonce &nonce) {
  VaultHeader header{};

  auto out = header.begin();

  out = std::copy(meta_salt.begin(), meta_salt.end(), out);
  out = std::copy(master_salt.begin(), master_salt.end(), out);
  std::copy(nonce.begin(), nonce.end(), out);

  return header;
}
