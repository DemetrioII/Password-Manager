#include "vault_storage/vault_serializer.h"

#include <filesystem>
#include <fstream>
#include <functional>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>
#include <sodium.h>

namespace {

const Argon2Salt &salt_bytes(const Salt &salt) {
  return std::get<Argon2Salt>(salt);
}

const XChaCha20Poly1305Nonce &nonce_bytes(const Nonce &nonce) {
  return std::get<XChaCha20Poly1305Nonce>(nonce);
}

// Adds a fully valid entry (encrypted password + fresh nonce) to `entries`.
void add_entry(password_manager::EncryptedEntries &entries, const Key &master_key,
               std::string id, std::string title, std::string login,
               std::string plaintext, std::string notes) {
  auto *e = entries.add_entries();
  e->set_id(std::move(id));
  e->set_title(std::move(title));
  e->set_login(std::move(login));
  e->set_notes(std::move(notes));

  Nonce nonce = NonceManager::generate<XChaCha20Poly1305Nonce>();
  std::visit(
      [&](const auto &n) {
        SecureString ciphertext =
            CryptoService::cypher(SecureString{plaintext}, n, master_key);
        e->set_password(ciphertext.data(), ciphertext.size());
        e->set_nonce(reinterpret_cast<const char *>(n.data()), n.size());
      },
      nonce);
}

// Builds a complete encrypted vault file whose inner entries are produced by
// `fill`, so tests can craft entries that stress the deserializer validation.
bool write_crafted_vault(
    const std::filesystem::path &path, const std::string &master_password,
    const std::function<void(password_manager::EncryptedEntries &,
                             const Key &)> &fill) {
  const Salt meta_salt = SaltManager::generateSalt<Argon2Salt>();
  const Salt master_salt = SaltManager::generateSalt<Argon2Salt>();
  const Salt ephemeral_salt = SaltManager::generateSalt<Argon2Salt>();

  vault::VaultKeys keys = vault::derive_keys_from_password(
      SecureString{master_password}, meta_salt, master_salt);

  password_manager::EncryptedEntries entries;
  fill(entries, keys.master_key);

  std::string serialized;
  if (!entries.SerializeToString(&serialized))
    return false;

  Nonce vault_nonce = NonceManager::generate<XChaCha20Poly1305Nonce>();
  const vault::VaultHeader header =
      vault::make_header(meta_salt, master_salt, ephemeral_salt, vault_nonce);

  std::vector<unsigned char> cipher_blob = CryptoService::encrypt(
      serialized.data(), serialized.size(), header.data(), header.size(),
      nonce_bytes(vault_nonce), keys.meta_key);

  password_manager::VaultProto proto;
  proto.set_meta_salt(reinterpret_cast<const char *>(salt_bytes(meta_salt).data()),
                      salt_bytes(meta_salt).size());
  proto.set_master_salt(
      reinterpret_cast<const char *>(salt_bytes(master_salt).data()),
      salt_bytes(master_salt).size());
  proto.set_ephemeral_salt(
      reinterpret_cast<const char *>(salt_bytes(ephemeral_salt).data()),
      salt_bytes(ephemeral_salt).size());
  proto.set_nonce(
      reinterpret_cast<const char *>(nonce_bytes(vault_nonce).data()),
      nonce_bytes(vault_nonce).size());
  proto.set_entries(reinterpret_cast<const char *>(cipher_blob.data()),
                    cipher_blob.size());

  std::string final_serialized;
  if (!proto.SerializeToString(&final_serialized))
    return false;

  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  if (!file)
    return false;
  file.write(final_serialized.data(),
             static_cast<std::streamsize>(final_serialized.size()));
  return file.good();
}

class VaultSerializerTest : public ::testing::Test {
protected:
  static void SetUpTestSuite() { ASSERT_EQ(sodium_init(), 0); }

  void SetUp() override {
    path_ = std::filesystem::temp_directory_path() /
            ("vault_serializer_test_" + std::to_string(getpid()) + ".vault");

    std::error_code ec;
    std::filesystem::remove(path_, ec);
  }

  void TearDown() override {
    std::error_code ec;
    std::filesystem::remove(path_, ec);
  }

  std::filesystem::path path_;
};

TEST_F(VaultSerializerTest, SerializeCreatesFile) {
  vault::Vault vault{SecureString{"hello"}};
  vault.Init();

  ASSERT_TRUE(vault.Add("GitHub", "alice", SecureString{"secret"}));

  const auto result = vault::Serializator::serialize(
      SecureString{"master-password"}, path_.string(), vault);

  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(std::filesystem::exists(path_));
  EXPECT_GT(std::filesystem::file_size(path_), 0u);
}

TEST_F(VaultSerializerTest, SerializeEmptyVaultCreatesFile) {
  vault::Vault vault{SecureString{"hello"}};
  vault.Init();

  const auto result = vault::Serializator::serialize(
      SecureString{"master-password"}, path_.string(), vault);

  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(std::filesystem::exists(path_));
  EXPECT_GT(std::filesystem::file_size(path_), 0u);
}

TEST_F(VaultSerializerTest, SerializeAndDeserializeEmptyVault) {
  vault::Vault original{SecureString{"fsuahf"}};
  original.Init();

  ASSERT_TRUE(vault::Serializator::serialize(SecureString{"master-password"},
                                             path_.string(), original));

  vault::Vault restored{SecureString{"wiuefi2wi"}};
  restored.Init();

  ASSERT_TRUE(vault::Serializator::deserialize(SecureString{"master-password"},
                                               path_.string(), restored));

  EXPECT_TRUE(restored.Entries().empty());
}

TEST_F(VaultSerializerTest, SerializeAndDeserializeRestoresEntry) {
  vault::Vault original{SecureString{"fiuwaf-ub88"}};
  original.Init();

  ASSERT_TRUE(original.Add("GitHub", "alice", SecureString{"super-secret"}));

  ASSERT_TRUE(vault::Serializator::serialize(SecureString{"master-password"},
                                             path_.string(), original));

  vault::Vault restored{SecureString{"fiuwaf-ub88werq"}};
  restored.Init();

  ASSERT_TRUE(vault::Serializator::deserialize(SecureString{"master-password"},
                                               path_.string(), restored));

  ASSERT_EQ(restored.Entries().size(), 1u);

  const auto &expected = original.Entries()[0];
  const auto &actual = restored.Entries()[0];

  EXPECT_EQ(actual.id, expected.id);
  EXPECT_EQ(actual.title, expected.title);
  EXPECT_EQ(actual.login, expected.login);
  EXPECT_EQ(actual.notes, expected.notes);
}

TEST_F(VaultSerializerTest, SerializeAndDeserializeRestoresMultipleEntries) {
  vault::Vault original{SecureString{"sdfuhq"}};
  original.Init();

  ASSERT_TRUE(
      original.Add("GitHub", "alice", SecureString{"github-password"}));

  ASSERT_TRUE(original.Add("Google", "bob", SecureString{"google-password"}));

  ASSERT_TRUE(original.Add("Server", "root", SecureString{"server-password"}));

  ASSERT_TRUE(vault::Serializator::serialize(SecureString{"master-password"},
                                             path_.string(), original));

  vault::Vault restored{SecureString{"iuef3"}};
  restored.Init();

  ASSERT_TRUE(vault::Serializator::deserialize(SecureString{"master-password"},
                                               path_.string(), restored));

  ASSERT_EQ(restored.Entries().size(), original.Entries().size());

  for (std::size_t i = 0; i < original.Entries().size(); ++i) {
    const auto &expected = original.Entries()[i];
    const auto &actual = restored.Entries()[i];

    EXPECT_EQ(actual.id, expected.id);
    EXPECT_EQ(actual.title, expected.title);
    EXPECT_EQ(actual.login, expected.login);
    EXPECT_EQ(actual.notes, expected.notes);
  }
}

TEST_F(VaultSerializerTest, DeserializeFailsWhenFileDoesNotExist) {
  vault::Vault vault{SecureString{"fha98h"}};
  vault.Init();

  const auto result = vault::Serializator::deserialize(
      SecureString{"master-password"}, path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::FileOpenFailed);
}

TEST_F(VaultSerializerTest, DeserializeFailsForEmptyFile) {
  {
    std::ofstream file(path_, std::ios::binary);
    ASSERT_TRUE(file);
  }

  vault::Vault vault{SecureString{"fsidhf9"}};
  vault.Init();

  const auto result = vault::Serializator::deserialize(
      SecureString{"master-password"}, path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::VaultCorrupted);
}

TEST_F(VaultSerializerTest, DeserializeFailsForInvalidProtobuf) {
  {
    std::ofstream file(path_, std::ios::binary);
    ASSERT_TRUE(file);

    const std::string garbage = "this is not a vault";
    file.write(garbage.data(), garbage.size());
  }

  vault::Vault vault{SecureString{"f8932q8h"}};
  vault.Init();

  const auto result = vault::Serializator::deserialize(
      SecureString{"master-password"}, path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::VaultCorrupted);
}

TEST_F(VaultSerializerTest, DeserializeFailsForWrongPassword) {
  vault::Vault original{SecureString{"siodf9iu"}};
  original.Init();

  ASSERT_TRUE(original.Add("GitHub", "alice", SecureString{"secret"}));

  ASSERT_TRUE(vault::Serializator::serialize(SecureString{"correct-password"},
                                             path_.string(), original)
                  .has_value());

  vault::Vault restored{SecureString{"fwuah-9hw"}};
  restored.Init();

  const auto result = vault::Serializator::deserialize(
      SecureString{"wrong-password"}, path_.string(), restored);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::CryptoError);

  EXPECT_TRUE(restored.Entries().empty());
}

TEST_F(VaultSerializerTest, DeserializeFailsWhenMetaSaltHasInvalidSize) {
  password_manager::VaultProto proto;

  proto.set_meta_salt("bad");
  proto.set_master_salt(std::string(crypto_pwhash_SALTBYTES, '\x01'));
  proto.set_ephemeral_salt(std::string(crypto_pwhash_SALTBYTES, '\x05'));
  proto.set_nonce(
      std::string(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, '\x02'));
  proto.set_entries("encrypted");

  std::string serialized;
  ASSERT_TRUE(proto.SerializeToString(&serialized));

  {
    std::ofstream file(path_, std::ios::binary);
    ASSERT_TRUE(file);
    file.write(serialized.data(), serialized.size());
  }

  vault::Vault vault{SecureString{"viudsa9-f"}};
  vault.Init();

  const auto result = vault::Serializator::deserialize(
      SecureString{"master-password"}, path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::VaultCorrupted);
}

TEST_F(VaultSerializerTest, DeserializeFailsWhenMasterSaltHasInvalidSize) {
  password_manager::VaultProto proto;

  proto.set_meta_salt(std::string(crypto_pwhash_SALTBYTES, '\x01'));
  proto.set_master_salt("bad");
  proto.set_ephemeral_salt(std::string(crypto_pwhash_SALTBYTES, '\x05'));
  proto.set_nonce(
      std::string(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, '\x02'));
  proto.set_entries("encrypted");

  std::string serialized;
  ASSERT_TRUE(proto.SerializeToString(&serialized));

  {
    std::ofstream file(path_, std::ios::binary);
    ASSERT_TRUE(file);
    file.write(serialized.data(), serialized.size());
  }

  vault::Vault vault{SecureString{"fsuhaf9"}};
  vault.Init();

  const auto result = vault::Serializator::deserialize(
      SecureString{"master-password"}, path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::VaultCorrupted);
}

TEST_F(VaultSerializerTest, DeserializeFailsWhenVaultNonceHasInvalidSize) {
  password_manager::VaultProto proto;

  proto.set_meta_salt(std::string(crypto_pwhash_SALTBYTES, '\x01'));
  proto.set_master_salt(std::string(crypto_pwhash_SALTBYTES, '\x02'));
  proto.set_ephemeral_salt(std::string(crypto_pwhash_SALTBYTES, '\x05'));
  proto.set_nonce("bad");
  proto.set_entries("encrypted");

  std::string serialized;
  ASSERT_TRUE(proto.SerializeToString(&serialized));

  {
    std::ofstream file(path_, std::ios::binary);
    ASSERT_TRUE(file);
    file.write(serialized.data(), serialized.size());
  }

  vault::Vault vault{SecureString{"fsuhaf9-8uq9-2w"}};
  vault.Init();

  const auto result = vault::Serializator::deserialize(
      SecureString{"master-password"}, path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::VaultCorrupted);
}

TEST_F(VaultSerializerTest, DeserializeFailsWhenEphemeralSaltHasInvalidSize) {
  password_manager::VaultProto proto;

  proto.set_meta_salt(std::string(crypto_pwhash_SALTBYTES, '\x01'));
  proto.set_master_salt(std::string(crypto_pwhash_SALTBYTES, '\x02'));
  proto.set_ephemeral_salt("bad");
  proto.set_nonce(
      std::string(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, '\x03'));

  proto.set_entries(
      std::string(crypto_aead_xchacha20poly1305_ietf_ABYTES, '\x04'));

  std::string serialized;
  ASSERT_TRUE(proto.SerializeToString(&serialized));

  {
    std::ofstream file(path_, std::ios::binary);
    ASSERT_TRUE(file);
    file.write(serialized.data(), serialized.size());
  }

  vault::Vault vault{SecureString{"fsuhaf9"}};
  vault.Init();

  const auto result = vault::Serializator::deserialize(
      SecureString{"master-password"}, path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::VaultCorrupted);
}

TEST_F(VaultSerializerTest, DeserializeFailsWhenEncryptedEntriesAreTooShort) {
  password_manager::VaultProto proto;

  proto.set_meta_salt(std::string(crypto_pwhash_SALTBYTES, '\x01'));
  proto.set_master_salt(std::string(crypto_pwhash_SALTBYTES, '\x02'));
  proto.set_ephemeral_salt(std::string(crypto_pwhash_SALTBYTES, '\x05'));
  proto.set_nonce(
      std::string(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, '\x03'));

  proto.set_entries(
      std::string(crypto_aead_xchacha20poly1305_ietf_ABYTES - 1, '\x04'));

  std::string serialized;
  ASSERT_TRUE(proto.SerializeToString(&serialized));

  {
    std::ofstream file(path_, std::ios::binary);
    ASSERT_TRUE(file);
    file.write(serialized.data(), serialized.size());
  }

  vault::Vault vault{SecureString{"f9uh-9auwg-9hf9[r 2h"}};
  vault.Init();

  const auto result = vault::Serializator::deserialize(
      SecureString{"master-password"}, path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::VaultCorrupted);
}

TEST_F(VaultSerializerTest, CorruptedEncryptedDataIsRejected) {
  vault::Vault original{SecureString{"soifh9-weh9"}};
  original.Init();

  ASSERT_TRUE(original.Add("GitHub", "alice", SecureString{"secret"}));

  ASSERT_TRUE(vault::Serializator::serialize(SecureString{"master-password"},
                                             path_.string(), original));

  std::string data;

  {
    std::ifstream file(path_, std::ios::binary);
    ASSERT_TRUE(file);

    data.assign(std::istreambuf_iterator<char>(file),
                std::istreambuf_iterator<char>());
  }

  ASSERT_FALSE(data.empty());

  // Corrupt the serialized protobuf itself.
  data[data.size() - 1] ^= 0x01;

  {
    std::ofstream file(path_, std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(file);

    file.write(data.data(), data.size());
  }

  vault::Vault restored{SecureString{"f9ua98h9-w20"}};
  restored.Init();

  const auto result = vault::Serializator::deserialize(
      SecureString{"master-password"}, path_.string(), restored);

  ASSERT_FALSE(result.has_value());

  EXPECT_TRUE(result.error() == vault::VaultError::VaultCorrupted ||
              result.error() == vault::VaultError::CryptoError);
}

TEST_F(VaultSerializerTest, ServiceSaveAndLoadRoundTrip) {
  vault::Vault original{SecureString{"vuwf8ufg9-q2h9h[932bi"}};
  original.Init();

  ASSERT_TRUE(original.Add("GitHub", "alice", SecureString{"secret"}));

  ASSERT_TRUE(vault::service::save(SecureString{"master-password"},
                                   path_.string(), original));

  vault::Vault restored{SecureString{"iufahf92"}};
  restored.Init();

  ASSERT_TRUE(vault::service::load(SecureString{"master-password"},
                                   path_.string(), restored));

  ASSERT_EQ(restored.Entries().size(), 1u);

  EXPECT_EQ(restored.Entries()[0].title, "GitHub");
  EXPECT_EQ(restored.Entries()[0].login, "alice");

  // EXPECT_EQ(restored.Entries()[0].password.decrypt(session_key).view(),
  // "secret");
}

TEST_F(VaultSerializerTest, SerializeLockedVaultReturnsVaultLocked) {
  vault::Vault vault{SecureString{"master"}};
  vault.Init();

  ASSERT_TRUE(vault.Add("GitHub", "alice", SecureString{"secret"}));

  vault.Lock();

  const auto result = vault::Serializator::serialize(
      SecureString{"master"}, path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::VaultLocked);
  EXPECT_FALSE(std::filesystem::exists(path_));
}

TEST_F(VaultSerializerTest, DeserializeRejectsDuplicateIds) {
  ASSERT_TRUE(write_crafted_vault(
      path_, "master-pw",
      [](password_manager::EncryptedEntries &entries, const Key &master_key) {
        add_entry(entries, master_key, "id-0001", "GitHub", "alice",
                  "secret-1", "n1");
        add_entry(entries, master_key, "id-0001", "GitHub", "bob", "secret-2",
                  "n2");
      }));

  vault::Vault vault{SecureString{"x"}};
  vault.Init();

  const auto result = vault::Serializator::deserialize(
      SecureString{"master-pw"}, path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::VaultCorrupted);
}

TEST_F(VaultSerializerTest, DeserializeRejectsEmptyId) {
  ASSERT_TRUE(write_crafted_vault(
      path_, "master-pw",
      [](password_manager::EncryptedEntries &entries, const Key &master_key) {
        add_entry(entries, master_key, "", "GitHub", "alice", "secret",
                  "notes");
      }));

  vault::Vault vault{SecureString{"x"}};
  vault.Init();

  const auto result = vault::Serializator::deserialize(
      SecureString{"master-pw"}, path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::VaultCorrupted);
}

TEST_F(VaultSerializerTest, DeserializeRejectsTooManyEntries) {
  constexpr int kMany = MAX_ENTRIES + 1;

  ASSERT_TRUE(write_crafted_vault(
      path_, "master-pw",
      [&](password_manager::EncryptedEntries &entries, const Key &master_key) {
        for (int i = 0; i < kMany; ++i) {
          add_entry(entries, master_key, "id-" + std::to_string(i),
                    "title-" + std::to_string(i), "login", "secret", "");
        }
      }));

  vault::Vault vault{SecureString{"x"}};
  vault.Init();

  const auto result = vault::Serializator::deserialize(
      SecureString{"master-pw"}, path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::VaultCorrupted);
}

TEST_F(VaultSerializerTest, DeserializeRejectsOversizeTitle) {
  ASSERT_TRUE(write_crafted_vault(
      path_, "master-pw",
      [](password_manager::EncryptedEntries &entries, const Key &master_key) {
        add_entry(entries, master_key, "id-0001",
                  std::string(MAX_TITLE_SIZE + 1, 'a'), "login", "secret",
                  "notes");
      }));

  vault::Vault vault{SecureString{"x"}};
  vault.Init();

  const auto result = vault::Serializator::deserialize(
      SecureString{"master-pw"}, path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::VaultCorrupted);
}

TEST_F(VaultSerializerTest, DeserializeRejectsOversizeLogin) {
  ASSERT_TRUE(write_crafted_vault(
      path_, "master-pw",
      [](password_manager::EncryptedEntries &entries, const Key &master_key) {
        add_entry(entries, master_key, "id-0001", "title",
                  std::string(MAX_LOGIN_SIZE + 1, 'a'), "secret", "notes");
      }));

  vault::Vault vault{SecureString{"x"}};
  vault.Init();

  const auto result = vault::Serializator::deserialize(
      SecureString{"master-pw"}, path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::VaultCorrupted);
}

TEST_F(VaultSerializerTest, DeserializeRejectsOversizeNotes) {
  ASSERT_TRUE(write_crafted_vault(
      path_, "master-pw",
      [](password_manager::EncryptedEntries &entries, const Key &master_key) {
        add_entry(entries, master_key, "id-0001", "title", "login", "secret",
                  std::string(MAX_NOTES_SIZE + 1, 'a'));
      }));

  vault::Vault vault{SecureString{"x"}};
  vault.Init();

  const auto result = vault::Serializator::deserialize(
      SecureString{"master-pw"}, path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::VaultCorrupted);
}

TEST_F(VaultSerializerTest, DeserializeRejectsOversizePassword) {
  ASSERT_TRUE(write_crafted_vault(
      path_, "master-pw",
      [](password_manager::EncryptedEntries &entries, const Key &master_key) {
        add_entry(entries, master_key, "id-0001", "title", "login",
                  std::string(MAX_PASSWORD_CIPHERTEXT_SIZE + 1, 'a'), "notes");
      }));

  vault::Vault vault{SecureString{"x"}};
  vault.Init();

  const auto result = vault::Serializator::deserialize(
      SecureString{"master-pw"}, path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::VaultCorrupted);
}

TEST_F(VaultSerializerTest, DeserializeRejectsOversizedFile) {
  {
    std::ofstream file(path_, std::ios::binary);
    ASSERT_TRUE(file);
    const std::string blob(MAX_VAULT_SIZE + 1, '\0');
    file.write(blob.data(), static_cast<std::streamsize>(blob.size()));
  }

  vault::Vault vault{SecureString{"x"}};
  vault.Init();

  const auto result = vault::Serializator::deserialize(
      SecureString{"master-pw"}, path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::VaultCorrupted);
}

TEST_F(VaultSerializerTest, FailedDeserializeLeavesVaultUnchanged) {
  vault::Vault original{SecureString{"session-a"}};
  original.Init();

  ASSERT_TRUE(original.Add("GitHub", "alice", SecureString{"secret-a"}));

  ASSERT_TRUE(vault::Serializator::serialize(SecureString{"master-a"},
                                             path_.string(), original));

  vault::Vault vault{SecureString{"session-unused"}};
  vault.Init();

  ASSERT_TRUE(vault::Serializator::deserialize(SecureString{"master-a"},
                                               path_.string(), vault));

  // Replace the file with a vault whose first entry is valid but whose second
  // entry has a corrupted nonce, so validation fails inside the entry loop.
  ASSERT_TRUE(write_crafted_vault(
      path_, "master-b",
      [](password_manager::EncryptedEntries &entries, const Key &master_key) {
        add_entry(entries, master_key, "id-0001", "GitHub", "alice",
                  "secret-1", "n1");

        auto *bad = entries.add_entries();
        bad->set_id("id-0002");
        bad->set_title("broken");
        bad->set_login("bob");
        bad->set_nonce("bad");
        bad->set_password("x");
      }));

  auto result = vault::Serializator::deserialize(SecureString{"master-b"},
                                                 path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::VaultCorrupted);

  // The previously loaded vault must be left untouched, including its session
  // key (so the stored password is still decryptable).
  ASSERT_EQ(vault.Entries().size(), 1u);
  EXPECT_EQ(vault.Entries()[0].title, "GitHub");

  auto password = vault.ShowPassword(vault.Entries()[0].id);
  ASSERT_TRUE(password.has_value());
  EXPECT_EQ(password->view(), "secret-a");
}

TEST_F(VaultSerializerTest, WriteAtomicCreatesOwnerOnlyFile) {
  vault::Vault vault{SecureString{"hello"}};
  vault.Init();

  ASSERT_TRUE(vault.Add("GitHub", "alice", SecureString{"secret"}));

  ASSERT_TRUE(vault::Serializator::serialize(SecureString{"master-password"},
                                             path_.string(), vault));

  struct stat st {};
  ASSERT_EQ(::stat(path_.c_str(), &st), 0);
  EXPECT_EQ(st.st_mode & 0777, 0600u);
}

TEST_F(VaultSerializerTest, WriteAtomicLeavesNoTempFiles) {
  vault::Vault vault{SecureString{"hello"}};
  vault.Init();

  ASSERT_TRUE(vault.Add("GitHub", "alice", SecureString{"secret"}));

  ASSERT_TRUE(vault::Serializator::serialize(SecureString{"master-password"},
                                             path_.string(), vault));

  // Overwrite the same path a second time.
  ASSERT_TRUE(vault::Serializator::serialize(SecureString{"master-password"},
                                             path_.string(), vault));

  const auto parent =
      path_.parent_path().empty() ? "." : path_.parent_path();

  for (const auto &entry : std::filesystem::directory_iterator(parent)) {
    const auto name = entry.path().filename().string();
    EXPECT_EQ(name.find(".tmp."), std::string::npos)
        << "leftover temp file: " << name;
  }
}

} // namespace
