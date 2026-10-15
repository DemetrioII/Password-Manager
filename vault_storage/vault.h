#pragma once
#include "crypto_service/crypto.h"
#include "vault_storage/proto/vault.pb.h"
#include "vault_storage/safe_writer.h"
#include "vault_storage/unlock_throttle.h"
#include "vault_storage/vault_model.hpp"
#include <expected>
#include <fcntl.h>
#include <optional>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace vault {
class Vault {
  friend class Serializator;

public:
  std::expected<void, VaultError> Add(PasswordEntry &&entry);
  std::expected<void, VaultError> Add(const std::string &title,
                                      const std::string &login,
                                      const SecureString &password);
  std::expected<void, VaultError> Remove(const UUID &);

  std::expected<const PasswordEntry *, VaultError> Find(const UUID &) const;

  const std::vector<PasswordEntry> &Entries() const;

  std::expected<SecureString, VaultError> ShowPassword(const UUID &) const;

  Vault(SecureString &&password,
        const UnlockThrottle::Config &throttle_config = {});

  void Lock();

  // Fast in-memory unlock. Only re-derives the session key from the stored
  // test ciphertext; it does not restore metadata wiped by Lock().
  bool Unlock(SecureString &&);

  // Unlock that restores metadata. It first validates the password against the
  // in-memory test ciphertext (updating the unlock throttle exactly like
  // Unlock), then, when a backing file is known, reloads salts/session key and
  // entry metadata from disk transactionally. Falls back to the fast in-memory
  // unlock when no path has been recorded yet.
  std::expected<void, VaultError> UnlockAndReload(SecureString &&password);

  [[nodiscard]] const std::string &path() const noexcept { return path_; }

  bool locked() const noexcept { return locked_; }

  void Init();

  Vault(Vault &&other) noexcept = default;


  std::expected<void, VaultError> Update(const UUID &id,
                                       const std::string &title,
                                       const std::string &login,
                                       const SecureString &password);

  std::expected<void, VaultError> SetNotes(const UUID &id,
                                          const std::string &notes);

  std::expected<void, VaultError> SetPassword(SecureString &&old,
                                            SecureString &&new_pw,
                                            const std::string &path);

private:
  // Verifies `password` against `test_magic_ciphertext` in constant time and
  // records the attempt with the unlock throttle. Returns the derived session
  // key on success, std::nullopt on a wrong password, or an error when the
  // session key could not be derived at all.
  std::expected<std::optional<EphemeralKey>, VaultError>
  deriveAndVerify(const SecureString &password);

  // Rejects operations on a vault whose constructor could not build a session
  // key (e.g. mlock/KDF failure) or that has been locked.
  std::expected<void, VaultError> ensureUnlocked() const;

  std::vector<PasswordEntry> entries_;
  Salt meta_salt_;
  Salt master_salt_;
  Salt ephemeral_salt_;
  std::optional<EphemeralKey> session_key_;
  std::optional<VaultError> init_error_;
  KdfProfile kdf_ = kCurrentKdfProfile;
  bool locked_ = false;
  UnlockThrottle throttle_;

  // Path this vault was last loaded from or saved to. Used by UnlockAndReload
  // to re-read metadata; empty until the first save/load (or SetPassword).
  std::string path_;

  SecureString test_magic_plaintext{"LENIN"};
  EncryptedField test_magic_ciphertext;
};

} // namespace vault
