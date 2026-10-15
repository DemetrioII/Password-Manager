#pragma once
#include <array>
#include <expected>
#include <filesystem>
#include <fstream>
#include <sodium.h>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <variant>

#define MAX_VAULT_SIZE (1024ULL * 1024ULL * 8ULL)
#define MAX_ENTRIES 1000
#define MAX_TITLE_SIZE 512
#define MAX_LOGIN_SIZE 1024
#define MAX_NOTES_SIZE 2048
#define MAX_PASSWORD_CIPHERTEXT_SIZE 2048

// Argon2id parameters, shared by every key derivation call site so they cannot
// drift apart. MODERATE is deliberately used instead of INTERACTIVE: password
// managers need stronger resistance to offline master-password brute force.
constexpr std::size_t kPwhashOpsLimit = crypto_pwhash_OPSLIMIT_MODERATE;
constexpr std::size_t kPwhashMemLimit = crypto_pwhash_MEMLIMIT_MODERATE;
constexpr int kPwhashAlgorithm = crypto_pwhash_ALG_ARGON2ID13;

// The KDF parameters a vault file declares. Vaults persist this so a future
// parameter bump does not orphan archives written with older parameters.
struct KdfProfile {
  std::size_t ops_limit;
  std::size_t mem_limit;
  int algorithm;

  friend bool operator==(const KdfProfile &, const KdfProfile &) = default;
};

constexpr KdfProfile kCurrentKdfProfile{kPwhashOpsLimit, kPwhashMemLimit,
                                        kPwhashAlgorithm};

// Every KDF profile this build can read. Loading is bounded by this table:
// a vault file cannot ask us to spend unbounded memory/CPU, and an unknown
// profile is rejected before any derivation happens.
constexpr KdfProfile kSupportedKdfProfiles[] = {kCurrentKdfProfile};

inline bool is_supported_kdf_profile(const KdfProfile &profile) {
  for (const KdfProfile &supported : kSupportedKdfProfiles) {
    if (profile == supported)
      return true;
  }
  return false;
}

enum class KeyManagerError {
  FileNotFound,
};

using Argon2Salt = std::array<std::byte, crypto_pwhash_SALTBYTES>;

using Salt = std::variant<Argon2Salt>;

using XChaCha20Poly1305Nonce =
    std::array<std::byte, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>;

using ChaCha20Poly1305Nonce =
    std::array<std::byte, crypto_aead_chacha20poly1305_ietf_NPUBBYTES>;

// The active alternative alone selects the AEAD primitive (and its nonce
// length), so a nonce of one length can never be fed to the wrong function.
using Nonce = std::variant<XChaCha20Poly1305Nonce, ChaCha20Poly1305Nonce>;

// Per-nonce-type AEAD parameters and libsodium entry points. Both primitives
// take the same argument shapes, so one template instantiation per nonce type
// is enough to dispatch every call site.
template <typename NonceT> struct AeadParams;

template <> struct AeadParams<XChaCha20Poly1305Nonce> {
  static constexpr std::size_t kNonceBytes =
      crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  static constexpr std::size_t kTagBytes =
      crypto_aead_xchacha20poly1305_ietf_ABYTES;
  static constexpr auto encrypt = crypto_aead_xchacha20poly1305_ietf_encrypt;
  static constexpr auto decrypt = crypto_aead_xchacha20poly1305_ietf_decrypt;
};

template <> struct AeadParams<ChaCha20Poly1305Nonce> {
  static constexpr std::size_t kNonceBytes =
      crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
  static constexpr std::size_t kTagBytes =
      crypto_aead_chacha20poly1305_ietf_ABYTES;
  static constexpr auto encrypt = crypto_aead_chacha20poly1305_ietf_encrypt;
  static constexpr auto decrypt = crypto_aead_chacha20poly1305_ietf_decrypt;
};

// Both supported AEADs must share key and tag sizes: `Key`/`EphemeralKey` are
// fixed 32-byte buffers and some buffers are sized from a single tag constant
// before dispatching on the nonce type. Enforced here so a future primitive
// swap cannot silently violate that assumption.
static_assert(crypto_aead_chacha20poly1305_ietf_KEYBYTES ==
              crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
static_assert(crypto_aead_chacha20poly1305_ietf_ABYTES ==
              crypto_aead_xchacha20poly1305_ietf_ABYTES);

// Tag/nonce sizes of the AEAD selected by the variant's active alternative.
inline std::size_t aead_tag_bytes(const Nonce &nonce) {
  return std::visit(
      [](const auto &value) {
        return AeadParams<std::decay_t<decltype(value)>>::kTagBytes;
      },
      nonce);
}

inline std::size_t aead_nonce_bytes(const Nonce &nonce) {
  return std::visit([](const auto &value) { return value.size(); }, nonce);
}

class CryptoError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

class InvalidCiphertext : public CryptoError {
  using CryptoError::CryptoError;
};

class AuthenticationFailed : public CryptoError {
  using CryptoError::CryptoError;
};

class KDFError : public std::runtime_error {
  using std::runtime_error::runtime_error;
};

template <typename T> const T &get(const Salt &salt) {
  return std::get<T>(salt);
}

template <typename T> const T &get(const Nonce &nonce) {
  return std::get<T>(nonce);
}

class NonceManager {
public:
  template <typename NonceType = XChaCha20Poly1305Nonce>
  static Nonce generate() {
    NonceType nonce;
    randombytes_buf(nonce.data(), nonce.size());
    return nonce;
  }

  [[nodiscard]]
  static std::expected<Nonce, KeyManagerError>
  read_from_file(const std::string &file_path) {
    Nonce nonce;
    std::ifstream nonce_file(file_path, std::ios::binary);

    if (!nonce_file) {
      return std::unexpected(KeyManagerError::FileNotFound);
    }

    std::visit(
        [&nonce_file](auto &nonce_value) {
          nonce_file.read(reinterpret_cast<char *>(nonce_value.data()),
                          nonce_value.size());
        },
        nonce);

    if (!nonce_file) {
      return std::unexpected(KeyManagerError::FileNotFound);
    }
    return nonce;
  }

  static void write_to_file(const std::string &file_path, const Nonce &nonce) {
    std::ofstream nonce_file(file_path, std::ios::binary);
    std::visit(
        [&nonce_file](const auto &nonce_value) {
          nonce_file.write(reinterpret_cast<const char *>(nonce_value.data()),
                           nonce_value.size());
        },
        nonce);
  }
};

class SaltManager {
public:
  static void saveToFile(const Salt &salt, const std::string &file_path) {
    std::ofstream salt_file(file_path, std::ios::binary);
    std::visit(
        [&salt_file](const auto &value) {
          salt_file.write(reinterpret_cast<const char *>(value.data()),
                          value.size());
        },
        salt);
  }

  template <typename SaltType> static Salt generateSalt() {
    SaltType salt;

    randombytes_buf(salt.data(), salt.size());
    return salt;
  }

  [[nodiscard]]
  static std::expected<Salt, KeyManagerError>
  getSaltFromFile(const std::string &file_path) {
    Salt salt;

    std::ifstream salt_file(file_path, std::ios::binary);

    if (!salt_file) {
      return std::unexpected(KeyManagerError::FileNotFound);
    }

    std::visit(
        [&salt_file](auto &value) {
          salt_file.read(reinterpret_cast<char *>(value.data()), value.size());
        },
        salt);

    if (!salt_file) {
      return std::unexpected(KeyManagerError::FileNotFound);
    }

    return salt;
  }
};

inline void lock_memory_or_fail(void *ptr, std::size_t size) {
  if (sodium_mlock(ptr, size) != 0) {
    throw std::runtime_error{"MLOCK failed: RLIMIT_MEMLOCK exhausted"};
  }
}
