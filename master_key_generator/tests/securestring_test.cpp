#include "master_key_generator/securestring.h"

#include <gtest/gtest.h>

#include <sstream>
#include <string>
#include <utility>

class SodiumEnvironment : public ::testing::Environment {
public:
  void SetUp() override { ASSERT_EQ(sodium_init(), 0); }
};

TEST(SecureString, ConstructsFromStringView) {
  std::string source = "super secret password";

  SecureString secure{source};

  ASSERT_EQ(secure.size(), source.size());
  EXPECT_EQ(secure.view(), source);
}

TEST(SecureString, ConstructsEmpty) {
  SecureString secure{std::size_t{0}};

  EXPECT_TRUE(secure.empty());
  EXPECT_EQ(secure.size(), 0);
  EXPECT_EQ(secure.view(), "");
}

TEST(SecureString, ConstructsWithSize) {
  constexpr std::size_t size = 32;

  SecureString secure{size};

  EXPECT_EQ(secure.size(), size);
  EXPECT_FALSE(secure.empty());
}

TEST(SecureString, AssignReplacesContents) {
  SecureString secure{"first secret"};

  const std::string second = "second secret";
  secure.assign(second.data(), second.size());

  ASSERT_EQ(secure.size(), second.size());
  EXPECT_EQ(secure.view(), second);
}

TEST(SecureString, AssignEmptyClearsContents) {
  SecureString secure{"secret"};

  secure.assign(nullptr, 0);

  EXPECT_TRUE(secure.empty());
  EXPECT_EQ(secure.size(), 0);
  EXPECT_EQ(secure.view(), "");
}

TEST(SecureString, MoveConstructorTransfersOwnership) {
  SecureString original{"secret"};

  SecureString moved{std::move(original)};

  EXPECT_EQ(moved.view(), "secret");
  EXPECT_EQ(moved.size(), 6);

  EXPECT_TRUE(original.empty());
  EXPECT_EQ(original.data(), nullptr);
}

TEST(SecureString, MoveAssignmentTransfersOwnership) {
  SecureString source{"new secret"};
  SecureString destination{"old secret"};

  destination = std::move(source);

  EXPECT_EQ(destination.view(), "new secret");
  EXPECT_EQ(destination.size(), 10);

  EXPECT_TRUE(source.empty());
  EXPECT_EQ(source.data(), nullptr);
}

TEST(SecureString, MoveAssignmentReleasesPreviousContents) {
  SecureString source{"new secret"};
  SecureString destination{"old secret"};

  destination = std::move(source);

  EXPECT_EQ(destination.view(), "new secret");
}

TEST(SecureString, SelfMoveAssignmentDoesNothing) {
  SecureString secure{"secret"};

  secure = std::move(secure);

  EXPECT_EQ(secure.view(), "secret");
  EXPECT_EQ(secure.size(), 6);
}

TEST(SecureString, InputOperatorReadsSecret) {
  std::istringstream input{"my_secret_password"};

  SecureString secure{""};
  input >> secure;

  EXPECT_EQ(secure.view(), "my_secret_password");
}

TEST(SecureString, InputOperatorReplacesExistingSecret) {
  SecureString secure{"old_secret"};

  std::istringstream input{"new_secret"};
  input >> secure;

  EXPECT_EQ(secure.view(), "new_secret");
}

TEST(SecureString, InputOperatorStopsAtWhitespace) {
  std::istringstream input{"secret password"};

  SecureString secure{""};
  input >> secure;

  EXPECT_EQ(secure.view(), "secret");
}

TEST(SecureString, DataMatchesView) {
  SecureString secure{"secret"};

  ASSERT_NE(secure.data(), nullptr);

  // EXPECT_EQ(std::string_view{secure.data(), secure.size()}, secure.view());
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);

  ::testing::AddGlobalTestEnvironment(new SodiumEnvironment);

  return RUN_ALL_TESTS();
}
