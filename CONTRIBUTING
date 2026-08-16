# Contributing to Password Manager

Thank you for your interest in contributing to **Password Manager**!

This project is primarily a learning and engineering project focused on building a secure password vault in modern C++. Contributions, reviews, bug reports and architectural discussions are welcome.

Because this project deals with cryptography and sensitive data, contributions require a little more care than a typical application.

---

## 📌 Before You Start

Please read the project [README](README.md) first.

Before making a significant change, especially an architectural or cryptographic one, please open an issue or start a discussion first.

Small fixes such as:

* documentation improvements;
* typo fixes;
* build fixes;
* tests;
* obvious bug fixes;

can usually go directly into a pull request.

For larger changes, discussing the design beforehand helps avoid implementing something that conflicts with the project's architecture.

---

## 🏗️ Development Environment

The project currently uses:

* **C++23**
* **Bazel**
* **Bzlmod**
* **Qt 6**
* **libsodium**
* **Protocol Buffers**
* **GoogleTest**

A C++23-compatible compiler and Bazel/Bazelisk are required.

Clone the repository:

```bash
git clone https://github.com/DemetrioII/Password-Manager.git
cd Password-Manager
```

Build the project:

```bash
bazelisk build //...
```

Run the tests:

```bash
bazelisk test //...
```

If you are working on the Qt interface, make sure your local Qt installation and Bazel Qt configuration are working correctly.

---

## 🌿 Branches

Create a separate branch for your change.

For example:

```bash
git checkout -b feature/password-generator
```

or:

```bash
git checkout -b fix/vault-unlock
```

Recommended prefixes:

```text
feature/     New functionality
fix/         Bug fixes
security/    Security-related changes
refactor/    Refactoring without intended behaviour changes
test/        Tests
docs/        Documentation
build/       Build system changes
```

Avoid committing directly to `main`.

---

## 💻 C++ Guidelines

The project uses modern C++.

Prefer:

* RAII;
* value semantics;
* smart pointers where ownership requires them;
* `std::string` / `std::vector` / standard containers;
* `std::span` for non-owning contiguous data;
* `std::expected` for recoverable errors;
* `constexpr` where it meaningfully improves the code;
* strong types instead of primitive values where appropriate.

Avoid introducing manual resource management when RAII can express the ownership safely.

For example, prefer:

```cpp
std::unique_ptr<Foo> foo = std::make_unique<Foo>();
```

over manually managing `new` and `delete`.

Likewise, resources such as files, sockets and locks should have clear ownership and lifetime.

---

## 🔐 Cryptography Rules

This is the most important section of this document.

### Do not implement cryptographic primitives yourself.

Do **not** add your own implementations of:

* AES;
* ChaCha;
* Poly1305;
* SHA;
* HMAC;
* Argon2;
* elliptic-curve cryptography;
* random number generators;
* or other cryptographic primitives.

Use well-established implementations provided by libraries such as **libsodium**.

The goal is to design the application's cryptographic protocol correctly, not to implement cryptographic primitives from scratch.

---

### Do not invent cryptography without discussion

Changing any of the following requires an architectural/security discussion before implementation:

* encryption algorithms;
* key derivation;
* salts;
* nonces;
* authentication;
* key hierarchy;
* vault file format;
* encryption order;
* password verification;
* secure memory handling.

A change that looks like a simple refactoring can completely change the security properties of the vault.

If you are unsure whether something is security-sensitive, assume that it is and ask first.

---

## 🧂 Salts and Nonces

Salts and nonces are not interchangeable.

A salt is used as an input to key derivation.

A nonce is used as an input to an encryption operation.

Do not:

* reuse a nonce where the encryption algorithm requires uniqueness;
* derive nonces from passwords;
* hard-code cryptographic randomness;
* use predictable values as cryptographic nonces;
* reuse salts where independent key derivation contexts are required.

Use the operating system's cryptographically secure random source through libsodium.

---

## 🔑 Keys and Sensitive Data

Cryptographic keys and decrypted passwords require special care.

Avoid:

```cpp
std::cout << key;
```

and similar logging of sensitive material.

Never commit:

* passwords;
* master keys;
* encryption keys;
* private keys;
* real vault files;
* production credentials;
* authentication tokens;
* test data containing real secrets.

If sensitive data accidentally appears in Git history, removing it from the latest commit is **not enough**. Notify the maintainer immediately.

---

## 🧹 Secure Memory Handling

Sensitive data should not live in memory longer than necessary.

Where appropriate, use libsodium's secure memory facilities and explicit memory wiping.

For example:

```cpp
sodium_memzero(buffer, size);
```

Do not assume that simply calling:

```cpp
buffer.clear();
```

securely erases the underlying memory.

The compiler may optimize ordinary memory writes in ways that make naïve clearing unsuitable for cryptographic secrets.

---

## 📦 Serialization

The vault uses Protocol Buffers for serialization.

Binary cryptographic material must be represented as binary data.

Do not store ciphertext, keys, salts or nonces in textual protobuf fields intended for UTF-8 strings.

Use:

```protobuf
bytes nonce = ...;
bytes ciphertext = ...;
```

rather than:

```protobuf
string nonce = ...;
```

unless there is a very deliberate encoding layer.

---

## 🚨 Error Handling

The project uses `std::expected` for operations which may fail.

Prefer explicit error propagation:

```cpp
auto result = vault.unlock(password);

if (!result) {
    return std::unexpected(result.error());
}
```

over exceptions for ordinary expected failures where the surrounding API is designed around `std::expected`.

Errors should describe **what went wrong**, without exposing sensitive information.

For example, avoid returning:

```text
"Wrong password: derived key was ABCDEF..."
```

Errors must never contain passwords, keys, plaintext credentials or other secrets.

---

## 🧪 Testing

Every non-trivial change should include tests where practical.

Security-sensitive code should have especially strong test coverage.

Examples include:

### Encryption

Test that:

* encryption followed by decryption returns the original plaintext;
* modified ciphertext fails authentication;
* modified nonce fails;
* incorrect keys fail;
* empty plaintext is handled correctly;
* binary data is handled correctly.

### Key derivation

Test that:

* the same password and salt produce the expected key;
* changing the password changes the derived key;
* changing the salt changes the derived key;
* invalid parameters are rejected.

### Vault

Test that:

* a locked vault cannot expose passwords;
* unlocking with the correct password succeeds;
* unlocking with an incorrect password fails;
* locking removes access to decrypted data;
* entries survive serialization/deserialization;
* corrupted vault files are rejected.

Whenever possible, tests should use deterministic test vectors rather than relying solely on random values.

---

## 🧪 Never Test With Real Passwords

Tests must use deliberately fake credentials.

Good:

```text
test-password-123
```

Bad:

```text
<your actual password>
```

Never use your personal passwords, API keys or credentials in tests.

---

## 📝 Commit Messages

Keep commit messages short and descriptive.

Good:

```text
vault: add lock and unlock operations
```

```text
crypto: use Argon2id for key derivation
```

```text
ui: add password search
```

```text
tests: cover corrupted vault files
```

Avoid messages such as:

```text
fix
```

```text
changes
```

```text
stuff
```

A commit should ideally represent one logical change.

---

## 🔍 Pull Requests

Before opening a pull request:

```bash
bazelisk build //...
bazelisk test //...
```

Make sure:

* the project builds successfully;
* tests pass;
* new functionality has appropriate tests;
* no debug output remains;
* no secrets are present;
* formatting is consistent;
* the change is limited to its intended purpose.

The pull request description should explain:

1. **What changed**
2. **Why it changed**
3. **How it was implemented**
4. **How it was tested**
5. **Whether the vault file format or cryptographic behaviour changed**

For security-sensitive changes, explicitly describe the security implications.

---

## 🔄 Vault Format Changes

Changes to the serialized vault format require special attention.

If a change modifies:

* protobuf messages;
* encrypted fields;
* salts;
* nonces;
* key derivation;
* metadata;
* version information;

the PR should explicitly state whether existing vault files remain readable.

If backwards compatibility is intentionally broken, explain why.

Ideally, format changes should include migration tests.

---

## 🛡️ Security Vulnerabilities

Please **do not publicly disclose a serious security vulnerability before giving the maintainer an opportunity to investigate it**.

A vulnerability may involve:

* key disclosure;
* plaintext password exposure;
* nonce reuse;
* authentication bypass;
* vault corruption;
* arbitrary file access;
* memory safety issues;
* insecure random number generation;
* authentication failures;
* cryptographic implementation mistakes.

For serious vulnerabilities, contact the maintainer privately before opening a public issue.

---

## 💬 Issues and Discussions

Issues are appropriate for:

* reproducible bugs;
* build problems;
* feature requests;
* documentation problems;
* usability issues.

For architectural questions, cryptographic design or potentially breaking changes, discussion before implementation is encouraged.

When reporting a bug, provide:

* operating system;
* compiler;
* compiler version;
* Bazel/Bazelisk version;
* relevant error message;
* steps to reproduce;
* expected behaviour;
* actual behaviour.

Never attach a real vault or real credentials to an issue.

---

## 🎨 Code Style

Keep the code readable and unsurprising.

Prefer clear code over clever code.

For example:

```cpp
if (vault.isLocked()) {
    return std::unexpected(VaultError::VaultLocked);
}
```

is preferable to compressing the same logic into unnecessarily complicated expressions.

Comments should explain **why**, not simply repeat **what** the code does.

Bad:

```cpp
// Increment i
++i;
```

Good:

```cpp
// Skip the metadata entry because it is not a user password.
++i;
```

---

## 🚫 What We Do Not Want

Please avoid introducing:

* unnecessary dependencies;
* custom cryptographic primitives;
* global mutable state;
* hard-coded paths;
* hard-coded secrets;
* unnecessary abstractions;
* unrelated refactoring in feature PRs;
* copied code without checking its license;
* security claims that have not been demonstrated or reviewed.

Especially avoid adding complexity simply because C++ allows it.

---

## 🧭 Project Philosophy

Password Manager is an opportunity to explore how a real security-sensitive application can be built from relatively low-level components.

The project values:

**Correctness over cleverness.**

**Explicitness over magic.**

**Testability over convenience.**

**Well-established cryptography over custom implementations.**

**Simple architecture over unnecessary abstraction.**

And most importantly:

> **Security is a property of the whole system, not a list of cryptographic algorithms.**

---

## ❤️ Final Note

Contributions do not have to be huge.

A good test, a clearer error message, a documentation fix, a security observation or a thoughtful code review can be just as valuable as a large feature.

If you are interested in the project, feel free to open an issue and start a discussion.

Thank you for helping make Password Manager better.

