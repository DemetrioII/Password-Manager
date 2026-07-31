#include "crypto_service/crypto.h"
#include <gtest/gtest.h>

class CryptoTest : public ::testing::Test {
protected:
};

int main() {
  sodium_init();
  ::testing::InitGoogleTest();
  return RUN_ALL_TESTS();
}
