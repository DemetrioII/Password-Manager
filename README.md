# 🔐 Password Manager

A password manager written in **modern C++** with a strong focus on security, cryptography and low-level software design.

> ⚠️ **Work in progress**
>
> This project is under active development and has **not been independently audited**. Do not use it as the only storage for real passwords or other critical secrets.

## ✨ Features

* 🔒 Encrypted password vault
* 🧂 Separate cryptographic salts for different purposes
* 🔑 Master-key derivation using **Argon2id**
* 🔐 **XChaCha20-Poly1305** authenticated encryption
* 🎲 Cryptographically secure random nonces
* 🗃️ Binary vault serialization using **Protocol Buffers**
* 🧹 Sensitive data handling and explicit vault locking
* 🛡️ Atomic file writes
* 🚦 Error handling with `std::expected`
* 🖥️ Qt-based graphical interface
* 🏗️ Bazel build system with Bzlmod
* 📦 Modular C++ architecture

## 🏛️ Architecture

The project is divided into several relatively independent components:

```text
                    ┌─────────────────────┐
                    │      Qt UI          │
                    │                     │
                    │  Password Manager   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    Vault Storage    │
                    │                     │
                    │  Lock / Unlock      │
                    │  Entries            │
                    │  Serialization      │
                    └───────┬─────┬───────┘
                            │     │
                ┌───────────┘     └────────────┐
                ▼                              ▼
      ┌──────────────────┐          ┌──────────────────┐
      │  Crypto Service  │          │ Master Key / KDF │
      │                  │          │                  │
      │ XChaCha20-       │          │ Argon2id         │
      │ Poly1305          │          │                  │
      └──────────────────┘          └──────────────────┘
```

### Vault

The `Vault` is the main abstraction responsible for managing password entries.

It supports operations such as:

* adding entries;
* removing entries;
* finding entries;
* locking the vault;
* unlocking the vault.

Operations which require access to decrypted data are rejected while the vault is locked.

### Key derivation

The master password is **not used directly as an encryption key**.

Instead, Argon2id is used to derive cryptographic keys from the master password.

Two independent salts are used:

```text
                 Master Password
                        │
              ┌─────────┴─────────┐
              │                   │
          meta salt           master salt
              │                   │
              ▼                   ▼
           Argon2id             Argon2id
              │                   │
              ▼                   ▼
          meta key            master key
```

The separation of keys allows different cryptographic purposes to use independent key material.

### Vault encryption

Password entries are encrypted individually before the complete serialized entry set is encrypted.

Conceptually:

```text
Password Entry
      │
      ▼
Serialize fields
      │
      ▼
Encrypt password ──────► per-entry nonce
      │
      ▼
Protocol Buffers
      │
      ▼
Encrypt serialized entries
      │
      └───────────────► vault nonce
      │
      ▼
Encrypted vault file
```

The vault-level encryption uses **XChaCha20-Poly1305**, while individual passwords are encrypted separately.

Nonces are generated independently for encryption operations.

## 🔐 Cryptography

The project currently relies on [libsodium](https://doc.libsodium.org/) rather than implementing cryptographic primitives itself.

Current cryptographic building blocks include:

| Purpose                       | Primitive          |
| ----------------------------- | ------------------ |
| Password-based key derivation | Argon2id           |
| Vault encryption              | XChaCha20-Poly1305 |
| Random data                   | libsodium CSPRNG   |
| Per-entry nonces              | Randomly generated |
| Serialization                 | Protocol Buffers   |

The current implementation derives both a **metadata key** and a **master key** from the same master password using independent salts.

### Why libsodium?

The project deliberately avoids implementing cryptographic primitives from scratch.

Cryptography is an area where "I can implement AES" is very different from "I can implement AES securely". Using a well-established cryptographic library greatly reduces the amount of security-critical code that has to be written and maintained.

## 📦 Data format

The vault is serialized using **Protocol Buffers**.

The encrypted file contains the information necessary to derive the keys and decrypt the vault, including:

* metadata salt;
* master-key salt;
* vault nonce;
* encrypted entries.

The actual password contents remain encrypted.

Binary cryptographic material is represented as `bytes` rather than text.

## 🧱 Project structure

```text
.
├── UI/
│   ├── UI.cpp
│   ├── UI.hpp
│   ├── main.cpp
│   ├── BUILD
│   └── dark.qss
│
├── crypto_service/
│   └── ...
│
├── master_key_generator/
│   └── ...
│
├── vault_storage/
│   └── ...
│
├── main.cpp
├── BUILD
├── MODULE.bazel
└── README.md
```

The repository currently separates the UI, cryptographic service, key generation and vault storage into independent Bazel targets.

## 🛠️ Tech Stack

* **C++23**
* **Bazel**
* **Bzlmod**
* **Qt**
* **libsodium**
* **Protocol Buffers**
* **GoogleTest**
* **nlohmann/json**

The dependency graph is managed through `MODULE.bazel`. The project currently uses C++23 and includes dependencies for libsodium, protobuf, Qt and GoogleTest.

## 🚀 Building

### Requirements

You will need:

* a C++23-compatible compiler;
* [Bazel](https://bazel.build/) or [Bazelisk](https://github.com/bazelbuild/bazelisk);
* Qt 6;
* the dependencies declared in `MODULE.bazel`.

Clone the repository:

```bash
git clone https://github.com/DemetrioII/Password-Manager.git
cd Password-Manager
```

Build the core application:

```bash
bazelisk build //:app
```

Build the graphical interface:

```bash
bazelisk build //UI:UI
```

Run the application:

```bash
bazelisk run //:app
```

Or run the Qt interface:

```bash
bazelisk run //UI:UI
```

> Build targets and platform-specific Qt configuration may change while the project is under development.

## 🧪 Testing

Tests are being developed alongside the core components.

The project uses **GoogleTest** for unit testing.

```bash
bazelisk test //...
```

## 🗺️ Roadmap

The project is still evolving. Planned areas include:

* [ ] Complete vault locking/unlocking workflow
* [ ] Improve secure memory handling
* [ ] Password generator
* [ ] Password search and filtering
* [ ] Better vault integrity checks
* [ ] More comprehensive unit tests
* [ ] Cryptographic test vectors
* [ ] Crash/recovery handling
* [ ] Improved Qt interface
* [ ] Vault import/export
* [ ] Secure vault transfer between devices
* [ ] One-time sharing links
* [ ] QR-based vault transfer
* [ ] Network transport with TLS
* [ ] Security review / external audit

## ⚠️ Security Notice

This project is primarily an **educational and engineering project**.

Although it uses modern cryptographic primitives and a dedicated cryptographic library, that does **not** automatically make the complete application secure.

Security depends on the entire system, including:

* key derivation;
* nonce management;
* authentication;
* serialization;
* memory handling;
* file handling;
* error handling;
* UI behaviour;
* operating-system security;
* backups and recovery;
* and the overall threat model.

The project has not undergone an independent security audit.

**Do not rely on it for protecting irreplaceable secrets yet.**

## 🤝 Contributing

Contributions, bug reports and security reviews are welcome.

If you find a potential security vulnerability, please avoid publishing sensitive exploit details in a public issue before discussing the problem with the maintainer.

## 📄 License

License information will be added as the project matures.

---

**Password Manager** — a small project about building a real password vault from the ground up in modern C++.

