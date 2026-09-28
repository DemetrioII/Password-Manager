#include "vault_storage/vault_model.hpp"

#include <algorithm>
#include <ranges>
#include <sodium.h>

#include <gtest/gtest.h>

namespace {

class VaultModelTest : public ::testing::Test {
protected:
  static void SetUpTestSuite() { ASSERT_EQ(sodium_init(), 0); }
};

TEST_F(VaultModelTest, MakeHeaderContainsMetaSaltMasterSaltEphemeralSaltAndNonce) {
  Salt meta_salt{};
  Salt master_salt{};
  Salt ephemeral_salt{};
  Nonce nonce{};

  std::visit(
      [](auto &master_salt_v, auto &meta_salt_v, auto &ephemeral_salt_v,
         auto &nonce_v) {
        std::ranges::fill(meta_salt_v, std::byte{0x11});
        std::ranges::fill(master_salt_v, std::byte{0x22});
        std::ranges::fill(ephemeral_salt_v, std::byte{0x44});
        std::ranges::fill(nonce_v, std::byte{0x33});

        const auto header =
            vault::make_header(meta_salt_v, master_salt_v, ephemeral_salt_v,
                               nonce_v);

        auto it = header.begin();

        EXPECT_TRUE(std::ranges::equal(
            meta_salt_v,
            std::ranges::subrange(it, it + meta_salt_v.size())));

        it += meta_salt_v.size();

        EXPECT_TRUE(std::ranges::equal(
            master_salt_v,
            std::ranges::subrange(it, it + master_salt_v.size())));

        it += master_salt_v.size();

        EXPECT_TRUE(std::ranges::equal(
            ephemeral_salt_v,
            std::ranges::subrange(it, it + ephemeral_salt_v.size())));

        it += ephemeral_salt_v.size();

        EXPECT_TRUE(std::ranges::equal(
            nonce_v, std::ranges::subrange(it, it + nonce_v.size())));
      },
      master_salt, meta_salt, ephemeral_salt, nonce);
}

TEST_F(VaultModelTest, MakeHeaderIsDeterministic) {
  Salt meta_salt{};
  Salt master_salt{};
  Salt ephemeral_salt{};
  Nonce nonce{};

  std::visit(
      [](auto &meta_salt_v, auto &master_salt_v, auto &ephemeral_salt_v,
         auto &nonce_v) {
        std::ranges::fill(meta_salt_v, std::byte{0x11});
        std::ranges::fill(master_salt_v, std::byte{0x22});
        std::ranges::fill(ephemeral_salt_v, std::byte{0x44});
        std::ranges::fill(nonce_v, std::byte{0x33});
      },
      meta_salt, master_salt, ephemeral_salt, nonce);

  const auto header1 =
      vault::make_header(meta_salt, master_salt, ephemeral_salt, nonce);

  const auto header2 =
      vault::make_header(meta_salt, master_salt, ephemeral_salt, nonce);

  EXPECT_EQ(header1, header2);
}

TEST_F(VaultModelTest, MakeHeaderChangesWhenMetaSaltChanges) {
  Salt meta_salt1{};
  Salt meta_salt2{};
  Salt master_salt{};
  Salt ephemeral_salt{};
  Nonce nonce{};

  std::visit(
      [](auto &meta_salt_v1, auto &meta_salt_v2) {
        std::ranges::fill(meta_salt_v1, std::byte{0x11});
        std::ranges::fill(meta_salt_v2, std::byte{0x22});
      },
      meta_salt1, meta_salt2);

  const auto header1 =
      vault::make_header(meta_salt1, master_salt, ephemeral_salt, nonce);

  const auto header2 =
      vault::make_header(meta_salt2, master_salt, ephemeral_salt, nonce);

  EXPECT_NE(header1, header2);
}

TEST_F(VaultModelTest, MakeHeaderChangesWhenMasterSaltChanges) {
  Salt meta_salt{};
  Salt master_salt1{};
  Salt master_salt2{};
  Salt ephemeral_salt{};
  Nonce nonce{};

  std::visit(
      [](auto &master_salt_v1, auto &master_salt_v2) {
        std::ranges::fill(master_salt_v1, std::byte{0x11});
        std::ranges::fill(master_salt_v2, std::byte{0x22});
      },
      master_salt1, master_salt2);

  const auto header1 =
      vault::make_header(meta_salt, master_salt1, ephemeral_salt, nonce);

  const auto header2 =
      vault::make_header(meta_salt, master_salt2, ephemeral_salt, nonce);

  EXPECT_NE(header1, header2);
}

TEST_F(VaultModelTest, MakeHeaderChangesWhenEphemeralSaltChanges) {
  Salt meta_salt{};
  Salt master_salt{};
  Salt ephemeral_salt1{};
  Salt ephemeral_salt2{};
  Nonce nonce{};

  std::visit(
      [](auto &ephemeral_salt_v1, auto &ephemeral_salt_v2) {
        std::ranges::fill(ephemeral_salt_v1, std::byte{0x11});
        std::ranges::fill(ephemeral_salt_v2, std::byte{0x22});
      },
      ephemeral_salt1, ephemeral_salt2);

  const auto header1 =
      vault::make_header(meta_salt, master_salt, ephemeral_salt1, nonce);

  const auto header2 =
      vault::make_header(meta_salt, master_salt, ephemeral_salt2, nonce);

  EXPECT_NE(header1, header2);
}

TEST_F(VaultModelTest, MakeHeaderChangesWhenNonceChanges) {
  Salt meta_salt{};
  Salt master_salt{};
  Salt ephemeral_salt{};
  Nonce nonce1{};
  Nonce nonce2{};

  std::visit(
      [](auto &nonce_v1, auto &nonce_v2) {
        std::ranges::fill(nonce_v1, std::byte{0x11});
        std::ranges::fill(nonce_v2, std::byte{0x22});
      },
      nonce1, nonce2);

  const auto header1 =
      vault::make_header(meta_salt, master_salt, ephemeral_salt, nonce1);

  const auto header2 =
      vault::make_header(meta_salt, master_salt, ephemeral_salt, nonce2);

  EXPECT_NE(header1, header2);
}

TEST_F(VaultModelTest, DeriveKeysProducesKeysOfCorrectSize) {
  const Salt meta_salt = SaltManager::generateSalt<Argon2Salt>();
  const Salt master_salt = SaltManager::generateSalt<Argon2Salt>();

  const auto keys = vault::derive_keys_from_password(
      SecureString{"correct horse battery staple"}, meta_salt, master_salt);

  EXPECT_EQ(keys.meta_key.size(), crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

  EXPECT_EQ(keys.master_key.size(),
            crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
}

TEST_F(VaultModelTest, DeriveKeysIsDeterministic) {
  const Salt meta_salt = SaltManager::generateSalt<Argon2Salt>();
  const Salt master_salt = SaltManager::generateSalt<Argon2Salt>();

  const auto keys1 = vault::derive_keys_from_password(
      SecureString{"correct horse battery staple"}, meta_salt, master_salt);

  const auto keys2 = vault::derive_keys_from_password(
      SecureString{"correct horse battery staple"}, meta_salt, master_salt);

  EXPECT_EQ(keys1.meta_key, keys2.meta_key);
  EXPECT_EQ(keys1.master_key, keys2.master_key);
}

TEST_F(VaultModelTest, MetaAndMasterKeysAreDifferent) {
  const Salt meta_salt = SaltManager::generateSalt<Argon2Salt>();
  const Salt master_salt = SaltManager::generateSalt<Argon2Salt>();

  const auto keys = vault::derive_keys_from_password(
      SecureString{"correct horse battery staple"}, meta_salt, master_salt);

  EXPECT_NE(keys.meta_key, keys.master_key);
}

TEST_F(VaultModelTest, DifferentPasswordsProduceDifferentKeys) {
  const Salt meta_salt = SaltManager::generateSalt<Argon2Salt>();
  const Salt master_salt = SaltManager::generateSalt<Argon2Salt>();

  const auto keys1 = vault::derive_keys_from_password(SecureString{"password1"},
                                                      meta_salt, master_salt);

  const auto keys2 = vault::derive_keys_from_password(SecureString{"password2"},
                                                      meta_salt, master_salt);

  EXPECT_NE(keys1.meta_key, keys2.meta_key);
  EXPECT_NE(keys1.master_key, keys2.master_key);
}

TEST_F(VaultModelTest, DifferentMetaSaltsProduceDifferentMetaKeys) {
  const Salt meta_salt1 = SaltManager::generateSalt<Argon2Salt>();
  const Salt meta_salt2 = SaltManager::generateSalt<Argon2Salt>();
  const Salt master_salt = SaltManager::generateSalt<Argon2Salt>();

  const auto keys1 = vault::derive_keys_from_password(SecureString{"password"},
                                                      meta_salt1, master_salt);

  const auto keys2 = vault::derive_keys_from_password(SecureString{"password"},
                                                      meta_salt2, master_salt);

  EXPECT_NE(keys1.meta_key, keys2.meta_key);

  // The master salt did not change, so the master key must remain identical.
  EXPECT_EQ(keys1.master_key, keys2.master_key);
}

TEST_F(VaultModelTest, DifferentMasterSaltsProduceDifferentMasterKeys) {
  const Salt meta_salt = SaltManager::generateSalt<Argon2Salt>();
  const Salt master_salt1 = SaltManager::generateSalt<Argon2Salt>();
  const Salt master_salt2 = SaltManager::generateSalt<Argon2Salt>();

  const auto keys1 = vault::derive_keys_from_password(SecureString{"password"},
                                                      meta_salt, master_salt1);

  const auto keys2 = vault::derive_keys_from_password(SecureString{"password"},
                                                      meta_salt, master_salt2);

  EXPECT_EQ(keys1.meta_key, keys2.meta_key);

  // The meta salt did not change, so the meta key must remain identical.
  EXPECT_NE(keys1.master_key, keys2.master_key);
}

} // namespace
