#include "vault.h"
#include <iostream>
#include <sodium.h>

int main() {
  sodium_init();
  Vault vault;

  PasswordEntry e;
  e.id = "0";
  e.login = "admin";
  e.password = "12345";

  PasswordEntry e2;
  e2.id = "1";
  e2.login = "2";
  e2.password = "hello";

  vault.Add(e);
  vault.Add(e2);

  Serializator serializator;
  serializator.serialize("vault.bin", vault);

  serializator.deserialize("vault.bin", vault);

  for (auto entry : vault.Entries()) {
    std::cout << entry.id << std::endl;
  }
  return 0;
}
