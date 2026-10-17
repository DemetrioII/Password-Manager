#pragma once
#include "vault_storage/vault_model.hpp"
#include <QString>

// User facing name of a vault cipher. The creation picker, the read-only
// indicator in the main window and the tests all render the enum through this,
// so a label can never drift away from the value it stands for.
inline QString cipherDisplayName(vault::CipherAlgorithm cipher) {
  switch (cipher) {
  case vault::CipherAlgorithm::XChaCha20Poly1305:
    return QStringLiteral("XChaCha20-Poly1305");
  case vault::CipherAlgorithm::ChaCha20Poly1305:
    return QStringLiteral("ChaCha20-Poly1305");
  }
  return QStringLiteral("Unknown cipher");
}