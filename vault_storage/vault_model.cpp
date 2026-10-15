#include "vault_storage/vault_model.hpp"

namespace {

template <typename UInt>
void append_little_endian(std::byte *&out, UInt value) {
  for (std::size_t i = 0; i < sizeof(UInt); ++i) {
    *out++ = static_cast<std::byte>((value >> (8 * i)) & 0xFF);
  }
}

} // namespace

vault::VaultKeys vault::derive_keys_from_password(SecureString &&password,
                                                  const Salt &salt_meta,
                                                  const Salt &salt_pass,
                                                  const KdfProfile &kdf) {
  VaultKeys keys;

  std::visit(
      [&password, &keys, &kdf](const auto &meta_salt, const auto &master_salt) {
        if (crypto_pwhash(
                keys.meta_key.data(), keys.meta_key.size(), password.view().data(),
                password.view().size(),
                reinterpret_cast<const unsigned char *>(meta_salt.data()),
                kdf.ops_limit, kdf.mem_limit, kdf.algorithm) != 0) {
          throw KDFError("Out of memory during Argon2id");
        }

        if (crypto_pwhash(
                keys.master_key.data(), keys.master_key.size(), password.view().data(),
                password.view().size(),
                reinterpret_cast<const unsigned char *>(master_salt.data()),
                kdf.ops_limit, kdf.mem_limit, kdf.algorithm) != 0) {
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
  VaultHeader header(crypto_pwhash_SALTBYTES * 3 + aead_nonce_bytes(nonce));

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

vault::VaultAad vault::make_aad(const VaultDescriptor &descriptor,
                                const VaultHeader &header) {
  VaultAad aad(kDescriptorBytes + header.size());

  std::byte *out = aad.data();

  append_little_endian(out, descriptor.version);
  append_little_endian(out, descriptor.kdf_algorithm);
  append_little_endian(out, descriptor.kdf_ops_limit);
  append_little_endian(out, descriptor.kdf_mem_limit);
  append_little_endian(out, descriptor.salt_algorithm);
  append_little_endian(out, descriptor.nonce_algorithm);
  append_little_endian(out, descriptor.cipher_algorithm);

  std::copy(header.begin(), header.end(), out);

  return aad;
}
