#include "vault_storage/vault_serializer.h"

#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>

#include <gtest/gtest.h>
#include <sodium.h>

namespace {

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

  static vault::PasswordEntry make_entry(std::string title, std::string login,
                                         const SecureString &password,
                                         std::string notes,
                                         const EphemeralKey &session_key) {
    vault::PasswordEntry entry;

    entry.title = std::move(title);
    entry.login = std::move(login);
    entry.notes = std::move(notes);
    entry.password = EncryptedField::encrypt(password, session_key);

    return entry;
  }

  std::filesystem::path path_;
};

TEST_F(VaultSerializerTest, SerializeCreatesFile) {
  vault::Vault vault{SecureString{"hello"}};
  vault.Init();

  EphemeralKey session_key{SecureString{"hello"}};

  ASSERT_TRUE(vault.Add(make_entry("GitHub", "alice", SecureString{"secret"},
                                   "test notes", session_key)));

  const auto result = vault::Serializator::serialize(
      SecureString{"master-password"}, path_.string(), vault);

  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(std::filesystem::exists(path_));
  EXPECT_GT(std::filesystem::file_size(path_), 0);
}

TEST_F(VaultSerializerTest, SerializeEmptyVaultCreatesFile) {
  vault::Vault vault{SecureString{"hello"}};
  vault.Init();

  EphemeralKey session_key;

  const auto result = vault::Serializator::serialize(
      SecureString{"master-password"}, path_.string(), vault);

  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(std::filesystem::exists(path_));
  EXPECT_GT(std::filesystem::file_size(path_), 0);
}

TEST_F(VaultSerializerTest, SerializeAndDeserializeEmptyVault) {
  vault::Vault original{SecureString{"fsuahf"}};
  original.Init();

  EphemeralKey session_key;

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

  EphemeralKey session_key{SecureString{"fiuwaf-ub88"}};

  ASSERT_TRUE(
      original.Add(make_entry("GitHub", "alice", SecureString{"super-secret"},
                              "my notes", session_key)));

  ASSERT_TRUE(vault::Serializator::serialize(SecureString{"master-password"},
                                             path_.string(), original));

  vault::Vault restored{SecureString{"fiuwaf-ub88werq"}};
  restored.Init();

  ASSERT_TRUE(vault::Serializator::deserialize(SecureString{"master-password"},
                                               path_.string(), restored));

  ASSERT_EQ(restored.Entries().size(), 1);

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

  EphemeralKey session_key{SecureString{"sdfuhq"}};

  ASSERT_TRUE(original.Add(make_entry("GitHub", "alice",
                                      SecureString{"github-password"},
                                      "GitHub notes", session_key)));

  ASSERT_TRUE(
      original.Add(make_entry("Google", "bob", SecureString{"google-password"},
                              "Google notes", session_key)));

  ASSERT_TRUE(
      original.Add(make_entry("Server", "root", SecureString{"server-password"},
                              "SSH server", session_key)));

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

  EphemeralKey session_key{SecureString{"fha98h"}};

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

  EphemeralKey session_key;

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

  EphemeralKey session_key;

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

  EphemeralKey session_key;

  const auto result = vault::Serializator::deserialize(
      SecureString{"master-password"}, path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::VaultCorrupted);
}

TEST_F(VaultSerializerTest, DeserializeFailsWhenMasterSaltHasInvalidSize) {
  password_manager::VaultProto proto;

  proto.set_meta_salt(std::string(crypto_pwhash_SALTBYTES, '\x01'));
  proto.set_master_salt("bad");
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

  EphemeralKey session_key;

  const auto result = vault::Serializator::deserialize(
      SecureString{"master-password"}, path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::VaultCorrupted);
}

TEST_F(VaultSerializerTest, DeserializeFailsWhenVaultNonceHasInvalidSize) {
  password_manager::VaultProto proto;

  proto.set_meta_salt(std::string(crypto_pwhash_SALTBYTES, '\x01'));
  proto.set_master_salt(std::string(crypto_pwhash_SALTBYTES, '\x02'));
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

  EphemeralKey session_key;

  const auto result = vault::Serializator::deserialize(
      SecureString{"master-password"}, path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::VaultCorrupted);
}

TEST_F(VaultSerializerTest, DeserializeFailsWhenEncryptedEntriesAreTooShort) {
  password_manager::VaultProto proto;

  proto.set_meta_salt(std::string(crypto_pwhash_SALTBYTES, '\x01'));
  proto.set_master_salt(std::string(crypto_pwhash_SALTBYTES, '\x02'));
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

  EphemeralKey session_key;

  const auto result = vault::Serializator::deserialize(
      SecureString{"master-password"}, path_.string(), vault);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), vault::VaultError::VaultCorrupted);
}

TEST_F(VaultSerializerTest, CorruptedEncryptedDataIsRejected) {
  vault::Vault original{SecureString{"soifh9-weh9"}};
  original.Init();

  EphemeralKey session_key;

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

  EphemeralKey session_key;

  ASSERT_TRUE(original.Add("GitHub", "alice", SecureString{"secret"}));

  ASSERT_TRUE(vault::service::save(SecureString{"master-password"},
                                   path_.string(), original));

  vault::Vault restored{SecureString{"iufahf92"}};
  restored.Init();

  ASSERT_TRUE(vault::service::load(SecureString{"master-password"},
                                   path_.string(), restored));

  ASSERT_EQ(restored.Entries().size(), 1);

  EXPECT_EQ(restored.Entries()[0].title, "GitHub");
  EXPECT_EQ(restored.Entries()[0].login, "alice");

  // EXPECT_EQ(restored.Entries()[0].password.decrypt(session_key).view(),
  // "secret");
}

} // namespace
