#include "vault_storage/vault.h"

#include <string>
#include <utility>

#include <gtest/gtest.h>
#include <sodium.h>

namespace {

class VaultTest : public ::testing::Test {
protected:
  static void SetUpTestSuite() { ASSERT_EQ(sodium_init(), 0); }
};

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
  ASSERT_EQ(vault.Entries().size(), 1);

  EXPECT_EQ(vault.Entries()[0].title, "GitHub");
  EXPECT_EQ(vault.Entries()[0].login, "alice");
  EXPECT_EQ(vault.Entries()[0].notes, "test notes");
}

TEST_F(VaultTest, AddGeneratesId) {
  vault::Vault vault{SecureString{"aa"}};
  vault.Init();

  ASSERT_TRUE(vault.Add(make_entry()));

  ASSERT_EQ(vault.Entries().size(), 1);

  const auto &id = vault.Entries()[0].id;

  EXPECT_EQ(id.size(), 16);
}

TEST_F(VaultTest, AddGeneratesUuidV4) {
  vault::Vault vault{SecureString{"afs"}};
  vault.Init();

  ASSERT_TRUE(vault.Add(make_entry()));

  const auto &id = vault.Entries()[0].id;

  ASSERT_EQ(id.size(), 16);

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

  ASSERT_EQ(vault.Entries().size(), 2);

  EXPECT_NE(vault.Entries()[0].id, vault.Entries()[1].id);
}

TEST_F(VaultTest, AddPreservesEntryData) {
  vault::Vault vault{SecureString{"aaa"}};
  vault.Init();

  auto entry = make_entry("My service", "user@example.com", "some notes");

  ASSERT_TRUE(vault.Add(std::move(entry)));

  ASSERT_EQ(vault.Entries().size(), 1);

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

  ASSERT_EQ(vault.Entries().size(), 1);

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

  ASSERT_EQ(vault.Entries().size(), 2);

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

  ASSERT_EQ(entries.size(), 3);

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

} // namespace
