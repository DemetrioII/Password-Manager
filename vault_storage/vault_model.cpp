#include "vault_storage/vault_model.hpp"

vault::VaultKeys vault::derive_keys_from_password(SecureString &&password,
                                                  const Salt &salt_meta,
                                                  const Salt &salt_pass) {
  VaultKeys keys;

  std::visit(
      [&password, &keys](const auto &meta_salt, const auto &master_salt) {
        if (crypto_pwhash(
                keys.meta_key.data(), keys.meta_key.size(), password.view().data(),
                password.view().size(),
                reinterpret_cast<const unsigned char *>(meta_salt.data()),
                kPwhashOpsLimit, kPwhashMemLimit, kPwhashAlgorithm) != 0) {
          throw KDFError("Out of memory during Argon2id");
        }

        if (crypto_pwhash(
                keys.master_key.data(), keys.master_key.size(), password.view().data(),
                password.view().size(),
                reinterpret_cast<const unsigned char *>(master_salt.data()),
                kPwhashOpsLimit, kPwhashMemLimit, kPwhashAlgorithm) != 0) {
          throw KDFError("Out of memory during Argon2id");
        }
      },
      salt_meta, salt_pass);

  return keys;
}

vault::VaultHeader vault::make_header(const Salt &meta_salt,
                                      const Salt &master_salt,
                                      const Salt &ephemeral_salt,
                                      const Nonce &nonce) {
  VaultHeader header{};

  auto out = header.begin();

  std::visit(
      [&out](const auto &meta_salt_v, const auto &master_salt_v,
             const auto &ephemeral_salt_v, const auto &nonce_v) {
        out = std::copy(meta_salt_v.begin(), meta_salt_v.end(), out);
        out = std::copy(master_salt_v.begin(), master_salt_v.end(), out);
        out = std::copy(ephemeral_salt_v.begin(), ephemeral_salt_v.end(), out);
        std::copy(nonce_v.begin(), nonce_v.end(), out);
      },
      meta_salt, master_salt, ephemeral_salt, nonce);

  return header;
}
