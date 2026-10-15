#include "vault_storage/vault.h"
#include "vault_storage/vault_serializer.h"

#include <chrono>
#include <filesystem>
#include <string>
#include <utility>

#include <gtest/gtest.h>
#include <sodium.h>

namespace {

class VaultTest : public ::testing::Test {
protected:
  static void SetUpTestSuite() { ASSERT_EQ(sodium_init(), 0); }
};

// A vault whose throttle is disabled, so unlock tests stay fast and
// deterministic. Production code paths keep the default (enabled) throttle.
vault::Vault VaultWithThrottlingDisabled(SecureString &&password) {
  const vault::UnlockThrottle::Config disabled{
      std::chrono::milliseconds::zero(), std::chrono::milliseconds::zero()};
  return vault::Vault(std::move(password), disabled);
}

vault::PasswordEntry make_entry(std::string title = "GitHub",
                                std::string login = "alice",
                                std::string notes = "test notes") {
  vault::PasswordEntry entry;
  entry.title = std::move(title);
  entry.login = std::move(login);
  entry.notes = std::move(notes);

  return entry;
}

// -----------------------------------------------------------------------------
// init()
// -----------------------------------------------------------------------------

TEST_F(VaultTest, NewVaultIsEmpty) {
  vault::Vault vault{SecureString{"e"}};

  EXPECT_TRUE(vault.Entries().empty());
}

TEST_F(VaultTest, InitKeepsVaultEmpty) {
  vault::Vault vault{SecureString{0}};

  vault.Init();

  EXPECT_TRUE(vault.Entries().empty());
}

// -----------------------------------------------------------------------------
// Add()
// -----------------------------------------------------------------------------

TEST_F(VaultTest, AddSucceeds) {
  vault::Vault vault{SecureString{"hello"}};
  vault.Init();

  auto result = vault.Add(make_entry());

  ASSERT_TRUE(result.has_value());
  ASSERT_EQ(vault.Entries().size(), 1u);

  EXPECT_EQ(vault.Entries()[0].title, "GitHub");
  EXPECT_EQ(vault.Entries()[0].login, "alice");
  EXPECT_EQ(vault.Entries()[0].notes, "test notes");
}

TEST_F(VaultTest, AddGeneratesId) {
  vault::Vault vault{SecureString{"aa"}};
  vault.Init();

  ASSERT_TRUE(vault.Add(make_entry()));

  ASSERT_EQ(vault.Entries().size(), 1u);

  const auto &id = vault.Entries()[0].id;

  EXPECT_EQ(id.size(), 16u);
}

TEST_F(VaultTest, AddGeneratesUuidV4) {
  vault::Vault vault{SecureString{"afs"}};
  vault.Init();

  ASSERT_TRUE(vault.Add(make_entry()));

  const auto &id = vault.Entries()[0].id;

  ASSERT_EQ(id.size(), 16u);

  // Version = 4.
  EXPECT_EQ(static_cast<unsigned char>(id[6]) & 0xF0, 0x40);

  // Variant = RFC 4122.
  EXPECT_EQ(static_cast<unsigned char>(id[8]) & 0xC0, 0x80);
}

TEST_F(VaultTest, AddGeneratesDifferentIds) {
  vault::Vault vault{SecureString{"hello"}};
  vault.Init();

  ASSERT_TRUE(vault.Add(make_entry("GitHub", "alice")));
  ASSERT_TRUE(vault.Add(make_entry("Google", "bob")));

  ASSERT_EQ(vault.Entries().size(), 2u);

  EXPECT_NE(vault.Entries()[0].id, vault.Entries()[1].id);
}

TEST_F(VaultTest, AddPreservesEntryData) {
  vault::Vault vault{SecureString{"aaa"}};
  vault.Init();

  auto entry = make_entry("My service", "user@example.com", "some notes");

  ASSERT_TRUE(vault.Add(std::move(entry)));

  ASSERT_EQ(vault.Entries().size(), 1u);

  const auto &stored = vault.Entries()[0];

  EXPECT_EQ(stored.title, "My service");
  EXPECT_EQ(stored.login, "user@example.com");
  EXPECT_EQ(stored.notes, "some notes");
}

// -----------------------------------------------------------------------------
// Find()
// -----------------------------------------------------------------------------

TEST_F(VaultTest, FindExistingEntry) {
  vault::Vault vault{SecureString{"hello"}};
  vault.Init();

  ASSERT_TRUE(vault.Add(make_entry()));

  const auto id = vault.Entries()[0].id;

  auto result = vault.Find(id);

  ASSERT_TRUE(result.has_value());
  ASSERT_NE(*result, nullptr);

  EXPECT_EQ((*result)->id, id);
  EXPECT_EQ((*result)->title, "GitHub");
  EXPECT_EQ((*result)->login, "alice");
}

TEST_F(VaultTest, FindMissingEntryReturnsEntryNotFound) {
  vault::Vault vault{SecureString{"£Wsaf"}};
  vault.Init();

  const vault::UUID id(16, '\0');

  auto result = vault.Find(id);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::EntryNotFound);
}

TEST_F(VaultTest, FindReturnsPointerToStoredEntry) {
  vault::Vault vault{SecureString{"hello"}};
  vault.Init();

  ASSERT_TRUE(vault.Add(make_entry()));

  const auto id = vault.Entries()[0].id;

  auto result = vault.Find(id);

  ASSERT_TRUE(result.has_value());
  ASSERT_NE(*result, nullptr);

  // (*result)->title = "Changed";

  EXPECT_NE(vault.Entries()[0].title, "Changed");
}

// -----------------------------------------------------------------------------
// Remove()
// -----------------------------------------------------------------------------

TEST_F(VaultTest, RemoveExistingEntry) {
  vault::Vault vault{SecureString{"£SF"}};
  vault.Init();

  ASSERT_TRUE(vault.Add(make_entry()));

  const auto id = vault.Entries()[0].id;

  auto result = vault.Remove(id);

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(vault.Entries().empty());
}

TEST_F(VaultTest, RemoveMissingEntryReturnsEntryNotFound) {
  vault::Vault vault{SecureString{"£"}};
  vault.Init();

  const vault::UUID id(16, '\0');

  auto result = vault.Remove(id);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::EntryNotFound);
}

TEST_F(VaultTest, RemoveOnlySpecifiedEntry) {
  vault::Vault vault{SecureString{"£as"}};
  vault.Init();

  ASSERT_TRUE(vault.Add(make_entry("GitHub", "alice")));

  ASSERT_TRUE(vault.Add(make_entry("Google", "bob")));

  const auto first_id = vault.Entries()[0].id;
  const auto second_id = vault.Entries()[1].id;

  ASSERT_TRUE(vault.Remove(first_id));

  ASSERT_EQ(vault.Entries().size(), 1u);

  EXPECT_EQ(vault.Entries()[0].id, second_id);

  EXPECT_EQ(vault.Entries()[0].title, "Google");
}

TEST_F(VaultTest, RemoveFirstEntryKeepsRemainingEntries) {
  vault::Vault vault{SecureString{"#sf2qa"}};
  vault.Init();

  ASSERT_TRUE(vault.Add(make_entry("First", "one")));

  ASSERT_TRUE(vault.Add(make_entry("Second", "two")));

  ASSERT_TRUE(vault.Add(make_entry("Third", "three")));

  const auto first_id = vault.Entries()[0].id;

  ASSERT_TRUE(vault.Remove(first_id));

  ASSERT_EQ(vault.Entries().size(), 2u);

  EXPECT_EQ(vault.Entries()[0].title, "Second");
  EXPECT_EQ(vault.Entries()[1].title, "Third");
}

// -----------------------------------------------------------------------------
// Entries()
// -----------------------------------------------------------------------------

TEST_F(VaultTest, EntriesReturnsAllEntries) {
  vault::Vault vault{SecureString{"£ntries"}};
  vault.Init();

  ASSERT_TRUE(vault.Add(make_entry("First", "one")));

  ASSERT_TRUE(vault.Add(make_entry("Second", "two")));

  ASSERT_TRUE(vault.Add(make_entry("Third", "three")));

  const auto &entries = vault.Entries();

  ASSERT_EQ(entries.size(), 3u);

  EXPECT_EQ(entries[0].title, "First");
  EXPECT_EQ(entries[1].title, "Second");
  EXPECT_EQ(entries[2].title, "Third");
}

TEST_F(VaultTest, EntriesPreservesInsertionOrder) {
  vault::Vault vault{SecureString{"£TYEW"}};
  vault.Init();

  ASSERT_TRUE(vault.Add(make_entry("A", "a")));

  ASSERT_TRUE(vault.Add(make_entry("B", "b")));

  ASSERT_TRUE(vault.Add(make_entry("C", "c")));

  ASSERT_EQ(vault.Entries()[0].title, "A");
  ASSERT_EQ(vault.Entries()[1].title, "B");
  ASSERT_EQ(vault.Entries()[2].title, "C");
}

// -----------------------------------------------------------------------------
// Lock / Unlock
// -----------------------------------------------------------------------------

TEST_F(VaultTest, LockThenUnlockWithCorrectPasswordRestoresAccess) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"master-password"});
  vault.Init();

  ASSERT_TRUE(vault.Add("GitHub", "alice", SecureString{"super-secret"}));
  const auto id = vault.Entries()[0].id;

  vault.Lock();
  ASSERT_TRUE(vault.locked());

  ASSERT_TRUE(vault.Unlock(SecureString{"master-password"}));

  auto password = vault.ShowPassword(id);
  ASSERT_TRUE(password.has_value());
  EXPECT_EQ(password->view(), "super-secret");
}

TEST_F(VaultTest, UnlockWithWrongPasswordFails) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"master-password"});
  vault.Init();

  ASSERT_TRUE(vault.Add("GitHub", "alice", SecureString{"super-secret"}));

  vault.Lock();

  EXPECT_FALSE(vault.Unlock(SecureString{"wrong-password"}));
}

TEST_F(VaultTest, LockedVaultRejectsSensitiveOperations) {
  vault::Vault vault{SecureString{"master-password"}};
  vault.Init();

  ASSERT_TRUE(vault.Add("GitHub", "alice", SecureString{"super-secret"}));
  const auto id = vault.Entries()[0].id;

  vault.Lock();

  EXPECT_EQ(vault.ShowPassword(id).error(), vault::VaultError::VaultLocked);
}

TEST_F(VaultTest, LockedVaultExposesNoEntries) {
  vault::Vault vault{SecureString{"master-password"}};
  vault.Init();

  ASSERT_TRUE(vault.Add("GitHub", "alice", SecureString{"super-secret"}));

  vault.Lock();

  EXPECT_TRUE(vault.Entries().empty());
}

TEST_F(VaultTest, ThrottleNeverRefusesCorrectPassword) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"master-password"});
  vault.Init();

  ASSERT_TRUE(vault.Add("GitHub", "alice", SecureString{"super-secret"}));

  vault.Lock();

  for (int i = 0; i < 50; ++i)
    EXPECT_FALSE(vault.Unlock(SecureString{"wrong-password"}));

  ASSERT_TRUE(vault.Unlock(SecureString{"master-password"}));
  EXPECT_FALSE(vault.locked());
}

// -----------------------------------------------------------------------------
// Combined behaviour
// -----------------------------------------------------------------------------

TEST_F(VaultTest, AddFindAndRemoveWorkTogether) {
  vault::Vault vault{SecureString{"743fw2afnx298rhf2r92hfubwuf9-2-qf929-"}};
  vault.Init();

  ASSERT_TRUE(vault.Add(make_entry("GitHub", "alice")));

  ASSERT_TRUE(vault.Add(make_entry("Google", "bob")));

  const auto github_id = vault.Entries()[0].id;
  const auto google_id = vault.Entries()[1].id;

  // Find GitHub.
  auto found = vault.Find(github_id);

  ASSERT_TRUE(found.has_value());
  EXPECT_EQ((*found)->title, "GitHub");

  // Remove GitHub.
  ASSERT_TRUE(vault.Remove(github_id));

  // GitHub is gone.
  auto missing = vault.Find(github_id);

  ASSERT_FALSE(missing.has_value());
  EXPECT_EQ(missing.error(), vault::VaultError::EntryNotFound);

  // Google is still there.
  found = vault.Find(google_id);

  ASSERT_TRUE(found.has_value());
  EXPECT_EQ((*found)->title, "Google");
}


TEST_F(VaultTest, UpdatePreservesUuidAndChangesFields) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"master-password"});
  vault.Init();
  ASSERT_TRUE(vault.Add("GitHub", "alice", SecureString{"secret"}));
  const auto id = vault.Entries()[0].id;
  ASSERT_TRUE(vault.Update(id, "New", "bob", SecureString{"secret2"}));
  ASSERT_EQ(vault.Entries().size(), 1u);
  EXPECT_EQ(vault.Entries()[0].id, id);
  EXPECT_EQ(vault.Entries()[0].title, "New");
  EXPECT_EQ(vault.Entries()[0].login, "bob");
  auto pw = vault.ShowPassword(id);
  ASSERT_TRUE(pw.has_value());
  EXPECT_EQ(pw->view(), "secret2");
}

TEST_F(VaultTest, UpdateMissingEntryReturnsEntryNotFound) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"p"});
  vault.Init();
  const vault::UUID id(16, '\0');
  auto res = vault.Update(id, "t", "l", SecureString{"x"});
  ASSERT_FALSE(res.has_value());
  EXPECT_EQ(res.error(), vault::VaultError::EntryNotFound);
}

TEST_F(VaultTest, UpdateLockedVaultReturnsVaultLocked) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"p"});
  vault.Init();
  ASSERT_TRUE(vault.Add("t", "l", SecureString{"x"}));
  const auto id = vault.Entries()[0].id;
  vault.Lock();
  auto res = vault.Update(id, "t", "l", SecureString{"x"});
  ASSERT_FALSE(res.has_value());
  EXPECT_EQ(res.error(), vault::VaultError::VaultLocked);
}

TEST_F(VaultTest, SetNotesWorks) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"p"});
  vault.Init();
  ASSERT_TRUE(vault.Add("t", "l", SecureString{"x"}));
  const auto id = vault.Entries()[0].id;
  ASSERT_TRUE(vault.SetNotes(id, "notes"));
  EXPECT_EQ(vault.Entries()[0].notes, "notes");
}

TEST_F(VaultTest, SetNotesMissingReturnsEntryNotFound) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"p"});
  vault.Init();
  const vault::UUID id(16, '\0');
  auto res = vault.SetNotes(id, "n");
  ASSERT_FALSE(res.has_value());
  EXPECT_EQ(res.error(), vault::VaultError::EntryNotFound);
}

TEST_F(VaultTest, SetNotesLockedReturnsVaultLocked) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"p"});
  vault.Init();
  ASSERT_TRUE(vault.Add("t", "l", SecureString{"x"}));
  const auto id = vault.Entries()[0].id;
  vault.Lock();
  auto res = vault.SetNotes(id, "n");
  ASSERT_FALSE(res.has_value());
  EXPECT_EQ(res.error(), vault::VaultError::VaultLocked);
}

TEST_F(VaultTest, AddRejectsOversizeTitle) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"p"});
  vault.Init();
  std::string big(MAX_TITLE_SIZE + 1, 'a');
  auto res = vault.Add(big, "l", SecureString{"x"});
  ASSERT_FALSE(res.has_value());
  EXPECT_EQ(res.error(), vault::VaultError::EntryTooLarge);
}

TEST_F(VaultTest, AddAcceptsTitleAtLimit) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"p"});
  vault.Init();
  std::string at_limit(MAX_TITLE_SIZE, 'a');
  auto res = vault.Add(at_limit, "l", SecureString{"x"});
  ASSERT_TRUE(res.has_value());
  EXPECT_EQ(vault.Entries()[0].title.size(),
            static_cast<std::size_t>(MAX_TITLE_SIZE));
}

TEST_F(VaultTest, AddRejectsOversizeLogin) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"p"});
  vault.Init();
  std::string big(MAX_LOGIN_SIZE + 1, 'a');
  auto res = vault.Add("t", big, SecureString{"x"});
  ASSERT_FALSE(res.has_value());
  EXPECT_EQ(res.error(), vault::VaultError::EntryTooLarge);
}

TEST_F(VaultTest, AddRejectsTooManyEntries) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"p"});
  vault.Init();
  for (int i = 0; i < MAX_ENTRIES; ++i) {
    ASSERT_TRUE(vault.Add("t" + std::to_string(i), "l", SecureString{"x"}));
  }
  auto res = vault.Add("t", "l", SecureString{"x"});
  ASSERT_FALSE(res.has_value());
  EXPECT_EQ(res.error(), vault::VaultError::TooManyEntries);
}

TEST_F(VaultTest, UpdateRejectsOversizeTitle) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"p"});
  vault.Init();
  ASSERT_TRUE(vault.Add("t", "l", SecureString{"x"}));
  const auto id = vault.Entries()[0].id;
  std::string big(MAX_TITLE_SIZE + 1, 'a');
  auto res = vault.Update(id, big, "l", SecureString{"x"});
  ASSERT_FALSE(res.has_value());
  EXPECT_EQ(res.error(), vault::VaultError::EntryTooLarge);
}

TEST_F(VaultTest, SetNotesRejectsOversize) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"p"});
  vault.Init();
  ASSERT_TRUE(vault.Add("t", "l", SecureString{"x"}));
  const auto id = vault.Entries()[0].id;
  std::string big(MAX_NOTES_SIZE + 1, 'a');
  auto res = vault.SetNotes(id, big);
  ASSERT_FALSE(res.has_value());
  EXPECT_EQ(res.error(), vault::VaultError::EntryTooLarge);
}

TEST_F(VaultTest, SetPasswordRejectsWrongOldPassword) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"old"});
  vault.Init();
  ASSERT_TRUE(vault.Add("t", "l", SecureString{"pw"}));
  vault.Lock();
  ASSERT_TRUE(vault.Unlock(SecureString{"old"}));
  const std::string path = std::filesystem::temp_directory_path() / "setpw_bad.vault";
  auto res = vault.SetPassword(SecureString{"wrong"}, SecureString{"new"}, path);
  ASSERT_FALSE(res.has_value());
  EXPECT_EQ(res.error(), vault::VaultError::WrongPassword);
}

TEST_F(VaultTest, SetPasswordWorksAndChangesPassword) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"old"});
  vault.Init();
  ASSERT_TRUE(vault.Add("t", "l", SecureString{"pw"}));
  const std::string path = std::filesystem::temp_directory_path() / "setpw_ok.vault";
  auto res = vault.SetPassword(SecureString{"old"}, SecureString{"new"}, path);
  ASSERT_TRUE(res.has_value());
  vault.Lock();
  ASSERT_FALSE(vault.Unlock(SecureString{"old"}));
  ASSERT_TRUE(vault.Unlock(SecureString{"new"}));
}

// -----------------------------------------------------------------------------
// UnlockAndReload()
// -----------------------------------------------------------------------------

TEST_F(VaultTest, UnlockAndReloadRestoresMetadataAfterLock) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"master-password"});
  vault.Init();
  ASSERT_TRUE(vault.Add("GitHub", "alice", SecureString{"super-secret"}));
  const auto id = vault.Entries()[0].id;
  ASSERT_TRUE(vault.SetNotes(id, "test notes"));

  const auto path =
      std::filesystem::temp_directory_path() / "reload_restore.vault";
  ASSERT_TRUE(vault::service::save(SecureString{"master-password"},
                                   path.string(), vault)
                  .has_value());
  EXPECT_EQ(vault.path(), path.string());

  vault.Lock();
  ASSERT_TRUE(vault.locked());
  EXPECT_TRUE(vault.Entries().empty());

  auto result = vault.UnlockAndReload(SecureString{"master-password"});
  ASSERT_TRUE(result.has_value());
  EXPECT_FALSE(vault.locked());

  ASSERT_EQ(vault.Entries().size(), 1u);
  EXPECT_EQ(vault.Entries()[0].id, id);
  EXPECT_EQ(vault.Entries()[0].title, "GitHub");
  EXPECT_EQ(vault.Entries()[0].login, "alice");
  EXPECT_EQ(vault.Entries()[0].notes, "test notes");

  auto password = vault.ShowPassword(id);
  ASSERT_TRUE(password.has_value());
  EXPECT_EQ(password->view(), "super-secret");
}

TEST_F(VaultTest, UnlockAndReloadWrongPasswordKeepsVaultLocked) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"master-password"});
  vault.Init();
  ASSERT_TRUE(vault.Add("GitHub", "alice", SecureString{"super-secret"}));

  const auto path =
      std::filesystem::temp_directory_path() / "reload_wrong.vault";
  ASSERT_TRUE(vault::service::save(SecureString{"master-password"},
                                   path.string(), vault)
                  .has_value());

  vault.Lock();

  auto wrong = vault.UnlockAndReload(SecureString{"wrong-password"});
  ASSERT_FALSE(wrong.has_value());
  EXPECT_EQ(wrong.error(), vault::VaultError::WrongPassword);
  EXPECT_TRUE(vault.locked());
  // Metadata is not leaked while locked.
  EXPECT_TRUE(vault.Entries().empty());

  // A retry with the right password still succeeds and restores metadata.
  auto good = vault.UnlockAndReload(SecureString{"master-password"});
  ASSERT_TRUE(good.has_value());
  ASSERT_EQ(vault.Entries().size(), 1u);
  EXPECT_EQ(vault.Entries()[0].title, "GitHub");
}

TEST_F(VaultTest, UnlockAndReloadWithoutPathFallsBackToFastUnlock) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"master-password"});
  vault.Init();
  ASSERT_TRUE(vault.Add("GitHub", "alice", SecureString{"super-secret"}));
  const auto id = vault.Entries()[0].id;

  EXPECT_TRUE(vault.path().empty());

  vault.Lock();

  auto result = vault.UnlockAndReload(SecureString{"master-password"});
  ASSERT_TRUE(result.has_value());
  EXPECT_FALSE(vault.locked());

  // Without a backing file the decrypted password is usable again even though
  // the wiped metadata cannot be recovered.
  auto password = vault.ShowPassword(id);
  ASSERT_TRUE(password.has_value());
  EXPECT_EQ(password->view(), "super-secret");
}

// -----------------------------------------------------------------------------
// F-01: password size invariant (writer must match reader limits)
// -----------------------------------------------------------------------------

namespace {
constexpr std::size_t kMaxPasswordPlaintext =
    MAX_PASSWORD_CIPHERTEXT_SIZE - crypto_aead_xchacha20poly1305_ietf_ABYTES;
} // namespace

TEST_F(VaultTest, AddAcceptsPasswordAtCiphertextLimit) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"p"});
  vault.Init();

  SecureString at_limit{std::string(kMaxPasswordPlaintext, 'a')};

  auto res = vault.Add("t", "l", at_limit);
  ASSERT_TRUE(res.has_value());
  ASSERT_EQ(vault.Entries().size(), 1u);
  EXPECT_EQ(vault.Entries()[0].password.ciphertext.size(),
            static_cast<std::size_t>(MAX_PASSWORD_CIPHERTEXT_SIZE));
}

TEST_F(VaultTest, AddRejectsPasswordAboveCiphertextLimit) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"p"});
  vault.Init();

  SecureString over_limit{std::string(kMaxPasswordPlaintext + 1, 'a')};

  auto res = vault.Add("t", "l", over_limit);
  ASSERT_FALSE(res.has_value());
  EXPECT_EQ(res.error(), vault::VaultError::EntryTooLarge);
  EXPECT_TRUE(vault.Entries().empty());
}

TEST_F(VaultTest, AddRejectsOversizePasswordCiphertext) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"p"});
  vault.Init();

  vault::PasswordEntry entry;
  entry.title = "t";
  entry.login = "l";
  entry.password.ciphertext.assign(MAX_PASSWORD_CIPHERTEXT_SIZE + 1, 0);
  entry.password.nonce = NonceManager::generate<XChaCha20Poly1305Nonce>();

  auto res = vault.Add(std::move(entry));
  ASSERT_FALSE(res.has_value());
  EXPECT_EQ(res.error(), vault::VaultError::EntryTooLarge);
  EXPECT_TRUE(vault.Entries().empty());
}

TEST_F(VaultTest, UpdateRejectsPasswordAboveCiphertextLimit) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"p"});
  vault.Init();
  ASSERT_TRUE(vault.Add("t", "l", SecureString{"old"}));
  const auto id = vault.Entries()[0].id;
  const auto original_size = vault.Entries()[0].password.ciphertext.size();

  SecureString over_limit{std::string(kMaxPasswordPlaintext + 1, 'a')};

  auto res = vault.Update(id, "t", "l", over_limit);
  ASSERT_FALSE(res.has_value());
  EXPECT_EQ(res.error(), vault::VaultError::EntryTooLarge);
  EXPECT_EQ(vault.Entries()[0].password.ciphertext.size(), original_size);
}

TEST_F(VaultTest, PasswordAtLimitSurvivesSaveAndLoad) {
  auto vault = VaultWithThrottlingDisabled(SecureString{"master-password"});
  vault.Init();

  SecureString at_limit{std::string(kMaxPasswordPlaintext, 'p')};
  ASSERT_TRUE(vault.Add("title", "login", at_limit));
  const auto id = vault.Entries()[0].id;

  const auto path =
      std::filesystem::temp_directory_path() / "password_at_limit.vault";
  ASSERT_TRUE(vault::service::save(SecureString{"master-password"},
                                   path.string(), vault)
                  .has_value());

  auto reloaded = VaultWithThrottlingDisabled(SecureString{"unused"});
  ASSERT_TRUE(vault::service::load(SecureString{"master-password"},
                                   path.string(), reloaded)
                  .has_value());
  ASSERT_EQ(reloaded.Entries().size(), 1u);

  auto restored = reloaded.ShowPassword(id);
  ASSERT_TRUE(restored.has_value());
  EXPECT_EQ(restored->size(), kMaxPasswordPlaintext);

  std::error_code ec;
  std::filesystem::remove(path, ec);
}
} // namespace
