#pragma once
#include "master_key_generator/securestring.h"
#include <QByteArray>
#include <QString>
#include <cstddef>
#include <sodium.h>
#include <string_view>

// Turns widget text into a locked SecureString without leaving an unlocked
// std::string/std::string_view copy of the secret behind: the intermediate
// QByteArray is zeroed before it is destroyed. The QString owned by the widget
// itself is out of this helper's reach.
inline SecureString toSecureString(const QString &text) {
  QByteArray utf8 = text.toUtf8();
  SecureString secure{std::string_view{
      utf8.constData(), static_cast<std::size_t>(utf8.size())}};
  sodium_memzero(utf8.data(), static_cast<std::size_t>(utf8.size()));
  return secure;
}
