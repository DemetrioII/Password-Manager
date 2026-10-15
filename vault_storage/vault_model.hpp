#pragma once
#include "master_key_generator/encryptedfield.h"
#include "master_key_generator/masterkey.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace vault {
using UUID = std::string;

// Vault file format version written by this build. Files without a version
// field are legacy v0. Readers reject anything above this.
inline constexpr std::uint32_t kVaultFormatVersion = 1;

// Numeric algorithm identifiers stored in v1 vault files. They mirror the
// enum numbering in vault_storage/proto/vault.proto and are bound into the
// AAD so a file cannot be silently re-interpreted as a different algorithm.
inline constexpr std::uint32_t kKdfAlgorithmArgon2id13 = 1;
inline constexpr std::uint32_t kSaltAlgorithmArgon2 = 1;
inline constexpr std::uint32_t kNonceAlgorithmXChaCha20Poly1305 = 1;
inline constexpr std::uint32_t kCipherAlgorithmXChaCha20Poly1305 = 1;

// The format metadata that is authenticated (as AAD) but not itself encrypted.
// It lives in the file header and its canonical encoding is fed to the AEAD for
// every v1 vault, so tampering with the declared version, KDF parameters or
// algorithms is detected as an authentication failure instead of a downgrade.
struct VaultDescriptor {
  std::uint32_t version = kVaultFormatVersion;
  std::uint32_t kdf_algorithm = kKdfAlgorithmArgon2id13;
  std::uint64_t kdf_ops_limit = kCurrentKdfProfile.ops_limit;
  std::uint64_t kdf_mem_limit = kCurrentKdfProfile.mem_limit;
  std::uint32_t salt_algorithm = kSaltAlgorithmArgon2;
  std::uint32_t nonce_algorithm = kNonceAlgorithmXChaCha20Poly1305;
  std::uint32_t cipher_algorithm = kCipherAlgorithmXChaCha20Poly1305;
};

enum class VaultError {
  WrongPassword,
  VaultCorrupted,
  InvalidFormat,
  IoError,
  CryptoError,
  FileOpenFailed,
  AuthenticationFailed,
  SaltCorrupted,
  NonceCorrupted,
  EntryNotFound,
  VaultLocked,
  OutOfMemory,
  SerializationFailed,
  EntryTooLarge,
  TooManyEntries,
};

enum class FileIoError {
  TempFileCreationFailed,
  WriteFailed,
  SyncFailed,
  RenameFailed,
  PermissionSetFailed,
};

struct PasswordEntry {
  UUID id;
  std::string title;
  std::string login;
  EncryptedField password;

  std::string notes;

  // Purges the plaintext in-memory metadata. The `id` (needed for lookup) and
  // the password ciphertext (still usable after a fast unlock) are preserved.
  void wipeMetadata() noexcept {
    sodium_memzero(title.data(), title.size());
    sodium_memzero(login.data(), login.size());
    sodium_memzero(notes.data(), notes.size());
  }
};

inline void wipe(PasswordEntry &entry) {
  sodium_memzero(entry.password.ciphertext.data(),
                 entry.password.ciphertext.size());
  std::visit([](auto &nonce) { sodium_memzero(nonce.data(), nonce.size()); },
             entry.password.nonce);
  entry.wipeMetadata();
}

struct VaultKeys {
  Key meta_key;
  Key master_key;
};

using VaultHeader =
    std::array<std::byte, crypto_pwhash_SALTBYTES * 3 +
                              crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>;

VaultHeader make_header(const Salt &meta_salt, const Salt &master_salt,
                        const Salt &ephemeral_salt, const Nonce &nonce);

// Fixed-width, endian-independent encoding of the format descriptor. The exact
// bytes are part of the AAD contract: any change breaks compatibility with
// existing v1 files, so this layout must never be altered without a version
// bump.
inline constexpr std::size_t kDescriptorBytes = 4 + 4 + 8 + 8 + 4 + 4 + 4;

using VaultAad = std::array<std::byte, kDescriptorBytes + VaultHeader{}.size()>;

// AAD for v1 vaults: descriptor bytes followed by the salt/nonce header.
VaultAad make_aad(const VaultDescriptor &descriptor, const VaultHeader &header);

VaultKeys derive_keys_from_password(SecureString &&password,
                                    const Salt &salt_meta,
                                    const Salt &salt_pass,
                                    const KdfProfile &kdf = kCurrentKdfProfile);

} // namespace vault
