#pragma once
#include <chrono>
#include <cstdint>
#include <functional>
#include <random>
#include <thread>

namespace vault {
class UnlockThrottle {
public:
  struct Config {
    std::chrono::milliseconds base{100};
    std::chrono::milliseconds cap{std::chrono::seconds{30}};
  };

  using Sleeper = std::function<void(std::chrono::milliseconds)>;

  explicit UnlockThrottle(Config config, Sleeper sleeper = &default_sleeper);

  void RecordSuccess();
  void RecordFailure();

private:
  static void default_sleeper(std::chrono::milliseconds ms);

  Config config_;
  Sleeper sleeper_;
  std::mt19937 rng_{std::random_device{}()};
  std::uint32_t failures_ = 0;
};
} // namespace vault
