# 🔐 Password Manager

A password manager written in **modern C++** with a strong focus on security, cryptography and low-level software design.

![C++23](https://img.shields.io/badge/C%2B%2B-23-00599C?logo=c%2B%2B&logoColor=white)
![Bazel](https://img.shields.io/badge/build-Bazel%20%2B%20Bzlmod-43A047?logo=bazel&logoColor=white)
![Qt 6](https://img.shields.io/badge/UI-Qt%206-41CD52?logo=qt&logoColor=white)
![libsodium](https://img.shields.io/badge/crypto-libsodium-9C27B0)
![Platform](https://img.shields.io/badge/platform-Linux-37474F?logo=linux&logoColor=white)
![Status](https://img.shields.io/badge/status-work%20in%20progress-orange)

> ⚠️ **Work in progress**
>
> This project is under active development and has **not been independently audited**. Do not use it as the only storage for real passwords or other critical secrets.

## ✨ Features

* 🔒 **Encrypted password vault** with an explicit lock / unlock workflow
* 🏷️ **Versioned on-disk format (v2)** — vault files carry their version, KDF parameters and algorithm identifiers, and legacy **v0/v1** files are still readable
* 🧂 **Three independent salts** (metadata, master key, session) and three separate keys
* 🔑 Master-key derivation using **Argon2id**, with the declared profile validated against an allow-list *before* any derivation
* 🔐 Selectable **authenticated encryption** — **XChaCha20-Poly1305** (default) or **ChaCha20-Poly1305**, both at per-entry and vault level, with the cipher dispatched from the nonce type
* 🎲 Cryptographically secure random nonces, freshly generated per operation
* 🧬 **AAD** binds the version, KDF parameters and algorithm ids to the vault ciphertext, so tampering and version downgrades are detected
* ♻️ **Rekeying** — change the master password and re-encrypt every entry (`Vault::SetPassword`)
* ✏️ **Entry mutation** — update an entry while preserving its UUID, and set notes
* 📏 **Consistent size limits** between writing and reading, so a saved vault is always re-loadable
* 🧹 **Secure memory handling** — `Key`/`EphemeralKey` enforce `mlock`; `SecureString` uses guard pages and best-effort locking; secrets are wiped with `sodium_memzero`
* 🛡️ **Process hardening** — core dumps disabled, process made non-dumpable, and the address space locked into RAM where the platform permits it
* 🚦 **Non-throwing public API** — recoverable errors use `std::expected` and `VaultError`, never exceptions
* ⏱️ **Unlock throttling** — exponential backoff on failed unlock attempts
* 🧱 **Atomic file writes** (`mkstemp` → `fsync` → `rename` → directory `fsync`), owner-only permissions
* 🔑 Built-in **password generator** with a configurable policy
* 🖥️ **Qt 6** graphical interface with a real startup flow and a dark theme
* 🧪 Comprehensive **GoogleTest** suite, including offscreen Qt form tests
* 🏗️ **Bazel + Bzlmod** build system with dedicated hardening configs
* 📦 Modular C++ architecture

## 🏛️ Architecture

The project is divided into several relatively independent components:

```text
                    ┌─────────────────────┐
                    │       Qt UI         │
                    │  Start / Unlock /   │
                    │  Main window        │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐        ┌────────────────────┐
                    │    Vault Storage    │◄───────│ Password Generator │
                    │  Lock / Unlock      │        └────────────────────┘
                    │  Entries / Rekey    │
                    │  Serialization v2   │
                    │  Atomic writes      │
                    └───┬─────────┬───────┘
                        │         │
            ┌───────────┘         └────────────┐
            ▼                                  ▼
  ┌──────────────────┐               ┌──────────────────────┐
  │  Crypto Service  │               │  Master Key / KDF    │
  │                  │               │                      │
  │  XChaCha20- /    │               │  Argon2id            │
  │  ChaCha20-       │               │  Key / SecureString  │
  │  Poly1305        │               │                      │
  └──────────────────┘               └──────────────────────┘

  ┌──────────────────────────────────────────────────────────┐
  │  Process Hardening  ·  applied before anything else       │
  │  RLIMIT_CORE=0 · PR_SET_DUMPABLE=0 · mlockall             │
  └──────────────────────────────────────────────────────────┘
```

### Vault

The `Vault` is the main abstraction responsible for managing password entries.

It supports operations such as:

* adding entries (with size validation);
* removing entries;
* finding and listing entries;
* updating an entry while keeping its UUID;
* setting notes;
* changing the master password and re-encrypting everything (**rekey**);
* locking the vault;
* unlocking the vault.

Operations which require access to decrypted data are rejected while the vault is locked. `Lock()` wipes the entry metadata from memory; unlocking can restore it from the backing file.

### Key derivation

The master password is **not used directly as an encryption key**.

Instead, Argon2id derives independent keys from the master password, each with its own salt:

```text
                          Master Password
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
    meta salt              master salt             ephemeral salt
        │                        │                        │
        ▼                        ▼                        ▼
     Argon2id               Argon2id                  Argon2id
        │                        │                        │
        ▼                        ▼                        ▼
     meta key               master key              session key
   (vault blob)         (entry passwords)          (in memory)
```

* the **meta key** encrypts the whole serialized entry set on disk;
* the **master key** encrypts individual password fields on disk;
* the **session key** protects decrypted passwords while they live in memory.

The separation of keys lets different cryptographic purposes use independent key material.

### Vault encryption

Password entries are encrypted individually before the complete serialized entry set is encrypted.

Conceptually:

```text
Password Entry (in memory, under session key)
      │
      ▼
Re-encrypt password under master key ──► per-entry nonce
      │
      ▼
Serialize entries with Protocol Buffers
      │
      ▼
Encrypt serialized entries under meta key ──► vault nonce
      │
      ▼
Encrypted vault file (v2)
```

The vault-level encryption uses **XChaCha20-Poly1305** or **ChaCha20-Poly1305** with the version/KDF/algorithm descriptor bound as **AAD**; individual passwords are encrypted separately under the master key. Nonces are generated independently for every encryption operation.

The cipher used when writing is a vault-wide setting (`Vault::set_cipher()`, default **XChaCha20-Poly1305**). It is picked in the creation dialog and shown read-only in the main window, where the loader has taken it from the open file. The same cipher applies to every per-entry and vault-level nonce in the file, and the reader selects it from the stored nonce length / algorithm ids — so each vault is written and read with one consistent cipher.

## 🔐 Cryptography

The project currently relies on [libsodium](https://doc.libsodium.org/) rather than implementing cryptographic primitives itself.

Current cryptographic building blocks include:

| Purpose                        | Primitive                    |
| ------------------------------ | ---------------------------- |
| Password-based key derivation  | Argon2id (`crypto_pwhash`)   |
| Key separation                 | `crypto_kdf_derive_from_key` |
| Entry & vault encryption       | XChaCha20-Poly1305 or ChaCha20-Poly1305 (IETF) |
| Random data                    | libsodium CSPRNG             |
| Secret comparison              | constant-time `sodium_memcmp`|
| Per-entry / vault nonces       | Randomly generated           |
| Serialization                  | Protocol Buffers             |

The current implementation derives a **metadata key** and a **master key** from the master password using independent salts, plus an **ephemeral session key** for in-memory protection.

### Why libsodium?

The project deliberately avoids implementing cryptographic primitives from scratch.

Cryptography is an area where "I can implement AES" is very different from "I can implement AES securely". Using a well-established cryptographic library greatly reduces the amount of security-critical code that has to be written and maintained.

## 📦 Data format (v2)

The vault is serialized using **Protocol Buffers** and written as a **versioned v2** descriptor.

The encrypted file contains the information necessary to derive the keys and decrypt the vault, including:

* the format **version** and the declared **KDF parameters** (algorithm, ops limit, memory limit);
* the **salt algorithm**, **nonce algorithm** and **cipher algorithm** identifiers;
* the metadata salt, master-key salt and ephemeral salt;
* the vault nonce;
* the encrypted entries.

The actual password contents remain encrypted. Binary cryptographic material is represented as `bytes` rather than text.

### AAD binding

Version, KDF parameters and algorithm ids are packed together with the salts and nonce into a canonical **little-endian AAD** (a fixed 36-byte descriptor layout — an on-disk contract — followed by the salt/nonce header). Any change to it, or a version downgrade, is detected as a `CryptoError`.

### Compatibility

* Declared KDF parameters are validated against a **supported-profile allow-list** before derivation, so a malicious file cannot force unbounded memory or CPU usage.
* Files without a version field are treated as **legacy v0**, read with the old header-only AAD.
* **v1** files (XChaCha20-Poly1305, fixed 24-byte nonce header) remain fully readable.
* **v2** files declare their cipher via the nonce/cipher algorithm ids; the reader derives the AEAD from the stored nonce length (12 bytes → ChaCha20-Poly1305, 24 bytes → XChaCha20-Poly1305), so a nonce can never be fed to the wrong primitive.
* Unknown or unsupported algorithms / KDF parameters, mismatched cipher/nonce ids, and future versions are rejected as `InvalidFormat` (malformed sizes as `VaultCorrupted`).

## 🛡️ Hardening

Security is treated as a whole-system property, not just a crypto problem:

* 🔒 **Secure memory** — `Key` and `EphemeralKey` are non-copyable, fail-closed on `sodium_mlock`, and wiped with `sodium_memzero`; `SecureString` is non-copyable, uses `sodium_malloc` guard pages, is read-only at rest, and wipes with `sodium_memzero`. Its `mlock` is best-effort, as libsodium documents.
* 🚫 **Process hardening** — `RLIMIT_CORE = 0` and `PR_SET_DUMPABLE = 0` are always fail-closed; `mlockall(MCL_CURRENT | MCL_FUTURE)` is fail-closed in native builds and best-effort in the container build (fallback to `MCL_CURRENT`, with a warning). Pass `--ulimit memlock=-1` to the container for full locking.
* ⏱️ **Unlock throttling** — exponential backoff (capped) on repeated failures, with no success-leaking fast path.
* 🧾 **Atomic writes** — temp file created with `mkstemp` (owner-only), fully written, `fsync`-ed, then atomically renamed, followed by a directory `fsync`.
* 🧯 **Defensive parsing** — field sizes, salt/nonce sizes, entry count and total file size are validated before use; unsupported inputs are rejected early.
* 🏗️ **Build hardening** — stack protector, control-flow protection, stack-clash protection, and full RELRO / non-exec stack link flags; `--config=strict` (warnings-as-errors on first-party packages) and `--config=release` (`_FORTIFY_SOURCE=2`, `NDEBUG`); optional `--config=asan` / `--config=ubsan`.

## 🧱 Project structure

```text
.
├── UI/                     # Qt 6 application (real entrypoint: //UI:UI)
│   ├── UI.cpp / UI.hpp     # Main window, entry widgets, clipboard hygiene
│   ├── main.cpp            # Startup flow: StartForm → MasterForm → window
│   ├── forms/              # Start / Master / Lock / Password / Save / Load forms
│   ├── tests/              # Offscreen Qt form tests
│   ├── dark.qss            # Dark theme
│   └── BUILD
│
├── crypto_service/         # XChaCha20-/ChaCha20-Poly1305 wrappers over libsodium
│
├── master_key_generator/   # Argon2id KDF, Key / SecureString / EphemeralKey,
│                           # EncryptedField, salts & nonce managers
│
├── vault_storage/          # Vault, serialization (v2), model & AAD,
│   ├── proto/              #   atomic safe writer, unlock throttle
│   │   └── vault.proto     # Vault protobuf schema
│   └── tests/              # Vault / serializer / model / throttle tests
│
├── password_generator/     # Policy-based password generator
│
├── process_hardening/      # Linux process hardening helpers
│
├── main.cpp                # //:app — currently a stub
├── BUILD
├── MODULE.bazel            # Bzlmod dependency graph
└── README.md
```

The repository separates the UI, cryptographic service, key generation, vault storage, password generation and process hardening into independent Bazel targets.

## 🛠️ Tech Stack

* **C++23** (set per-target via `copts`)
* **Bazel** + **Bzlmod** (no CMake / Makefile; `WORKSPACE` mode is disabled)
* **Qt 6** (via `rules_qt`, local SDK)
* **libsodium** (system library)
* **Protocol Buffers**
* **GoogleTest**

The dependency graph is managed through `MODULE.bazel`. The project currently uses C++23 and includes dependencies for protobuf, Qt and GoogleTest; libsodium is consumed as a system library.

## 🚀 Building

### Requirements

You will need:

* a C++23-compatible compiler;
* [Bazel](https://bazel.build/) or [Bazelisk](https://github.com/bazelbuild/bazelisk);
* Qt 6 with development headers;
* libsodium (`-lsodium`);
* the dependencies declared in `MODULE.bazel`.

Clone the repository:

```bash
git clone https://github.com/DemetrioII/Password-Manager.git
cd Password-Manager
```

Build everything:

```bash
bazelisk build //...
```

Build the graphical application (the real entrypoint):

```bash
bazelisk build //UI:UI
```

Build with the hardening profiles:

```bash
bazelisk build --config=strict //...        # -Wall -Wextra -Werror -Wshadow on first-party code
bazelisk build --config=release -c opt //... # _FORTIFY_SOURCE=2, NDEBUG
bazelisk build --config=asan //...           # AddressSanitizer
bazelisk build --config=ubsan //...          # UndefinedBehaviorSanitizer
```

Run the application:

```bash
bazelisk run //UI:UI
```

> ℹ️ `//:app` (the root `main.cpp`) is currently a stub. The real program is the Qt application `//UI:UI`.
>
> Build targets and platform-specific Qt configuration may change while the project is under development.

## 🧪 Testing

The project uses **GoogleTest** for unit testing. There is one `cc_test` target per test file, plus a set of offscreen Qt form tests.

```bash
bazelisk test //...
```

This runs the headless C++ library tests and the Qt form tests. The latter run under `QT_QPA_PLATFORM=offscreen` (no display or `xvfb` required).

To run a single target:

```bash
bazelisk test //vault_storage/tests:vault_test
```

## 🐳 Docker

A multi-stage `Dockerfile` builds the Qt application in Ubuntu 24.04 and copies only the release binary into a smaller runtime image. The image runs as the non-root `app` user (UID 10001) and exposes `/data` as a volume.

**Requirements**

* Docker with BuildKit (the Dockerfile uses cache mounts)
* An X11 session; the container uses the host display
* `xhost` (package `x11-xserver-utils`)

Allow local Docker containers to connect to the host X server, then build:

```bash
xhost +local:docker
docker build -t libre-passman .
```

Run the GUI:

```bash
docker run -it --rm \
  --ulimit memlock=-1:-1 \
  -e DISPLAY="$DISPLAY" \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  libre-passman:latest
```

Revoke the X11 access when you are done:

```bash
xhost -local:docker
```

`--ulimit memlock=-1:-1` gives the app enough locked memory, so it can lock its whole address space as in a native build. The image is compiled with the container hardening profile (`PM_CONTAINER_BUILD`): core dumps and `ptrace` are still blocked, but `mlockall()` is best-effort because Docker's default `RLIMIT_MEMLOCK` is usually too small. Without the ulimit the app still starts, but prints a warning and secrets may be swappable, so disable or encrypt swap. If your Docker daemon refuses to raise the limit, you can run as root with `--user 0 --cap-add=IPC_LOCK` (less isolated).

The container has an anonymous volume at `/data`. To keep vault files on the host, add `-v "$PWD:/data"`; if you do, you may also need `--user "$(id -u):$(id -g)"` or `chown` the directory so the container can write to it.

The published image lives in the GitHub Container Registry. The workflow in `.github/workflows/docker.yml` builds and pushes on every push to `main`, on `v*.*.*` tags, and manually via `workflow_dispatch`; pull requests only build.

```bash
docker pull ghcr.io/demetrioii/password-manager:latest
docker tag ghcr.io/demetrioii/password-manager:latest libre-passman:latest
```

The package is private by default; change its visibility in the repository's package settings if you want anonymous pulls. For Wayland, mount `$XDG_RUNTIME_DIR` and set `QT_QPA_PLATFORM=wayland`; for a headless check, set `QT_QPA_PLATFORM=offscreen`.

## 🗺️ Roadmap

The project is still evolving. Planned areas include:

**Done**

* [x] Vault format **v1** — versioned files, KDF parameters, algorithm ids, descriptor-bound AAD, legacy v0 migration
* [x] Vault format **v2** — selectable cipher (**XChaCha20-Poly1305** or **ChaCha20-Poly1305**), variable-length nonce header, v0/v1 compatibility
* [x] Separate salts and keys for metadata, master key and session
* [x] Secure memory handling (`mlock`, guard pages, wipes)
* [x] Process hardening (non-dumpable, `mlockall`, no core dumps)
* [x] Unlock throttling with exponential backoff
* [x] Rekeying and entry mutation (`SetPassword`, `Update`, `SetNotes`)
* [x] Consistent write/read size limits
* [x] Password generator
* [x] Qt startup flow, real unlock dialog, clipboard hygiene
* [x] Vault cipher selection in the creation dialog, with the cipher of the open file shown in the main window
* [x] Atomic, owner-only file writes

**Next**

* [ ] Auto-lock on idle / suspend
* [ ] UI for rekeying and editing notes
* [ ] Non-blocking unlock (Argon2 currently blocks the event loop)
* [ ] `.bak` backup and self-check on load
* [ ] Document Argon2 parameters vs. the OWASP floor + a benchmark target

**Stretch**

* [ ] CI (GitHub Actions with Bazel + ASan/UBSan)
* [ ] libFuzzer target on deserialization
* [ ] `clang-format` / `.clang-tidy`
* [ ] Threat-model document with explicit non-goals
* [ ] Vault import/export
* [ ] Vault timestamps
* [ ] TOTP / 2FA per entry
* [ ] Secure vault transfer between devices
* [ ] One-time sharing links
* [ ] QR-based vault transfer
* [ ] Network transport with TLS
* [ ] External security audit

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
