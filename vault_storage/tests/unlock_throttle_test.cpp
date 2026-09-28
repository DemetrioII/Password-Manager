#include "vault_storage/unlock_throttle.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

namespace {

using vault::UnlockThrottle;

struct DelayLog {
  std::vector<std::chrono::milliseconds> delays;
};

UnlockThrottle::Config ConfigWith(std::chrono::milliseconds base,
                                  std::chrono::milliseconds cap) {
  return UnlockThrottle::Config{base, cap};
}

std::chrono::milliseconds ThrottledDelay(UnlockThrottle::Config config,
                                         std::uint32_t failures) {
  DelayLog log;
  UnlockThrottle throttle(
      config, [&log](std::chrono::milliseconds d) { log.delays.push_back(d); });

  for (std::uint32_t i = 0; i < failures; ++i)
    throttle.RecordFailure();

  if (log.delays.empty())
    return std::chrono::milliseconds(0);
  return log.delays.back();
}

TEST(UnlockThrottle, BackoffGrowsExponentially) {
  const auto base = std::chrono::milliseconds(100);
  const auto cap = std::chrono::milliseconds(3600 * 1000);
  const auto config = ConfigWith(base, cap);

  DelayLog log;
  UnlockThrottle throttle(
      config, [&log](std::chrono::milliseconds d) { log.delays.push_back(d); });

  for (std::uint32_t i = 0; i < 4; ++i)
    throttle.RecordFailure();

  ASSERT_EQ(log.delays.size(), 4u);

  // Attempt n (0-based) sleeps in [base * 2^n, base * 2^n + base).
  auto floor = base;
  for (const auto delay : log.delays) {
    EXPECT_GE(delay, floor);
    EXPECT_LT(delay, floor + base);
    floor = std::min(cap, floor * 2);
  }
}

TEST(UnlockThrottle, CapIsRespected) {
  const auto base = std::chrono::milliseconds(100);
  const auto cap = std::chrono::milliseconds(500);
  const auto config = ConfigWith(base, cap);

  DelayLog log;
  UnlockThrottle throttle(
      config, [&log](std::chrono::milliseconds d) { log.delays.push_back(d); });

  for (std::uint32_t i = 0; i < 12; ++i)
    throttle.RecordFailure();

  ASSERT_EQ(log.delays.size(), 12u);

  // Capped backoff: every delay sits in [min(cap, base*2^n), +base).
  auto floor = base;
  for (const auto delay : log.delays) {
    EXPECT_GE(delay, floor);
    EXPECT_LT(delay, floor + base);
    EXPECT_LE(delay, cap + base);
    floor = std::min(cap, floor * 2);
  }

  EXPECT_EQ(std::min(cap, floor), cap);
}

TEST(UnlockThrottle, SuccessResetsFailureCounter) {
  const auto base = std::chrono::milliseconds(100);
  const auto config = ConfigWith(base, std::chrono::milliseconds(3600 * 1000));

  DelayLog log;
  UnlockThrottle throttle(
      config, [&log](std::chrono::milliseconds d) { log.delays.push_back(d); });

  throttle.RecordFailure();
  throttle.RecordFailure();
  throttle.RecordSuccess();
  throttle.RecordFailure();

  ASSERT_EQ(log.delays.size(), 3u);

  // After a success the counter resets: back to a fresh base-1 delay.
  EXPECT_GE(log.delays[2], base);
  EXPECT_LT(log.delays[2], base + base);
}

TEST(UnlockThrottle, ZeroConfigDoesNotSleep) {
  const auto config = ConfigWith(std::chrono::milliseconds::zero(),
                                 std::chrono::milliseconds::zero());

  DelayLog log;
  UnlockThrottle throttle(
      config, [&log](std::chrono::milliseconds d) { log.delays.push_back(d); });

  throttle.RecordFailure();
  throttle.RecordFailure();
  throttle.RecordFailure();
  throttle.RecordSuccess();

  EXPECT_TRUE(log.delays.empty());
  EXPECT_EQ(ThrottledDelay(config, 100u), std::chrono::milliseconds::zero());
}

TEST(UnlockThrottle, DefaultSleeperRunsWithoutThrowing) {
  UnlockThrottle throttle(ConfigWith(std::chrono::milliseconds(1),
                                     std::chrono::milliseconds(1)));

  EXPECT_NO_THROW(throttle.RecordFailure());
}

} // namespace