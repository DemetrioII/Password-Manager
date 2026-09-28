#include "vault_storage/unlock_throttle.h"

#include <algorithm>
#include <limits>
#include <random>
#include <utility>

void vault::UnlockThrottle::default_sleeper(std::chrono::milliseconds ms) {
  std::this_thread::sleep_for(ms);
}

vault::UnlockThrottle::UnlockThrottle(Config config, Sleeper sleeper)
    : config_(config), sleeper_(std::move(sleeper)) {}

void vault::UnlockThrottle::RecordSuccess() { failures_ = 0; }

void vault::UnlockThrottle::RecordFailure() {
  const uint32_t attempt = failures_;
  if (failures_ != std::numeric_limits<std::uint32_t>::max()) {
    ++failures_;
  }

  auto delay = config_.base;
  for (std::uint32_t steps = attempt; steps > 0 && delay < config_.cap;
       --steps) {
    delay = std::min(config_.cap, delay * 2);
  }

  auto jitter = std::chrono::milliseconds::zero();
  if (config_.base.count() > 0) {
    std::uniform_int_distribution<long> dist(0, config_.base.count() - 1);
    jitter = std::chrono::milliseconds(dist(rng_));
  }

  const auto total = delay + jitter;
  if (total > decltype(total)::zero())
    sleeper_(total);
}
