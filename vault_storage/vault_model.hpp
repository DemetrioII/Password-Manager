#pragma once
#include "master_key_generator/encryptedfield.h"
#include "master_key_generator/masterkey.h"
#include <algorithm>
#include <expected>
#include <string>

namespace vault {
using UUID = std::string;

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
  Nonce nonce;
  std::string notes;

  // Purges the plaintext in-memory metadata. The `id` (needed for lookup) and
  // the password ciphertext (still usable after a fast unlock) are preserved.
  void wipeMetadata() noexcept {
    std::fill(title.begin(), title.end(), '\0');
    std::fill(login.begin(), login.end(), '\0');
    std::fill(notes.begin(), notes.end(), '\0');
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

VaultKeys derive_keys_from_password(SecureString &&password,
                                    const Salt &salt_meta,
                                    const Salt &salt_pass);

} // namespace vault
