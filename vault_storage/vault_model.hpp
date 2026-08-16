#pragma once
#include "master_key_generator/encryptedfield.h"
#include "master_key_generator/masterkey.h"
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
  OutOfMemory
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
};

struct VaultKeys {
  Key meta_key;
  Key master_key;
};

using VaultHeader =
    std::array<std::byte, crypto_pwhash_SALTBYTES * 2 +
                              crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>;

VaultHeader make_header(const Salt &meta_salt, const Salt &master_salt,
                        const Nonce &nonce);

VaultKeys derive_keys_from_password(
    SecureString &&password,
    const std::array<std::byte, crypto_pwhash_SALTBYTES> &salt_meta,
    const std::array<std::byte, crypto_pwhash_SALTBYTES> &salt_pass);

} // namespace vault
