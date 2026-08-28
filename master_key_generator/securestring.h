#pragma once
#include <algorithm>
#include <sodium.h>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

class SecureString {
public:
  explicit SecureString(std::string_view data);
  explicit SecureString(std::size_t size);

  SecureString(const SecureString &) = delete;
  SecureString &operator=(const SecureString &) = delete;

  SecureString(SecureString &&) noexcept;
  SecureString &operator=(SecureString &&) noexcept;

  void assign(const char *data, std::size_t size);

  friend bool operator==(const SecureString &lhs, const SecureString &rhs);

  void clear() noexcept;

  [[nodiscard]] const char *data() const noexcept { return data_; }

  char *data() noexcept { return data_; }

  [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

  friend std::istream &operator>>(std::istream &is, SecureString &ss) {
    std::string buf;
    if (is >> buf) {
      ss.assign(buf.data(), buf.size());
      sodium_memzero(buf.data(), buf.size());
    }
    return is;
  }

  ~SecureString();

  std::string_view view() const noexcept;

  std::size_t size() const noexcept;

private:
  char *data_ = nullptr;
  std::size_t size_ = 0;
};
