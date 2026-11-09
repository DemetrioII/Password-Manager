# Security Policy

## Project status

**Password Manager** is an educational and engineering project: a C++23 password
vault with a Qt 6 UI, libsodium cryptography, and a protobuf on-disk format.

- The project has **not been independently audited**.
- It is **work in progress** and should **not** be used as the only storage for
  real passwords or other critical secrets.
- There is **no CI yet** (no `.github/` workflows in the repository).
- Using established primitives such as Argon2id and ChaCha20-Poly1305 does not
  make the whole application secure. Key derivation, nonce management,
  serialization, memory handling, file handling, UI behaviour, and the
  operating-system environment all matter.

## Supported versions

- Only the `main` branch of `https://github.com/DemetrioII/Password-Manager` is
  supported.
- **No release tags exist** and there is no supported-version matrix yet.
  Report findings against a concrete commit SHA (`git rev-parse HEAD`).
- Current on-disk vault format is **v2**
  (`kVaultFormatVersion = 2` in `vault_storage/vault_model.hpp`).
- Legacy **v0** (no `version` field) and **v1** files remain readable. Saving an
  older file silently upgrades it to v2; there is no downgrade path.
- A future `version` above the current one is rejected as
  `VaultError::InvalidFormat`.

## Reporting a vulnerability

Use GitHub private vulnerability reporting / Security Advisory:

**https://github.com/DemetrioII/Password-Manager/security/advisories/new**

- **Do not open a public issue for a serious finding.** Use the private advisory
  flow first.
- If private reporting is unavailable, contact the maintainer through the GitHub
  profile without publishing exploit details.
- Include:
  - commit SHA / branch;
  - operating system and architecture;
  - compiler and Bazel/Bazelisk version;
  - build configuration (`asan`, `ubsan`, `strict`, `release`, or default);
  - affected file, function, or class;
  - minimal reproduction steps and expected vs. actual behaviour;
  - impact and required attacker capabilities;
  - whether a real vault was involved.
- **Never attach real vaults, master passwords, keys, or personal credentials.**
  Use synthetic test vaults only.
- Response is **best-effort**. There is no bug bounty and no guaranteed response
  time or SLA.
- Coordinated disclosure is expected: allow reasonable time to investigate and
  fix before publishing details. The maintainer will coordinate a disclosure
  date with the reporter where possible.

## Rules of engagement for pentesters

- Test only vaults you created, or systems/data you are explicitly authorized to
  test.
- Do not test against other users' data, third-party systems, or production
  secrets.
- Avoid destructive or denial-of-service testing on shared systems. Keep
  resource-intensive experiments isolated.
- Use test passwords only (for example `test-password-123`); never use real
  credentials.
- The application calls `hardening::apply()` at startup, which sets
  `RLIMIT_CORE = 0`, `PR_SET_DUMPABLE = 0`, and
  `mlockall(MCL_CURRENT | MCL_FUTURE)`. Native builds fail closed if any of
  these calls fail. The container image is built with `PM_CONTAINER_BUILD`:
  the first two remain fail-closed, while `mlockall` is best-effort (falling
  back to `MCL_CURRENT`) because Docker's default `RLIMIT_MEMLOCK` is usually
  too small. Run the container with `--ulimit memlock=-1` for full memory
  locking.
- Argon2id derivation is deliberately expensive and currently blocks the UI
  event loop. Expect freezes during create, unlock, load, save, and rekey
  operations.
- Do not run destructive tests against real vault files. Copy them first and
  work in a temporary directory.

## Architecture and trust boundaries

- The real entrypoint is the Qt application `//UI:UI` (`UI/main.cpp`). The root
  target `//:app` (`main.cpp`) is only a stub that returns `0`.
- Main components:
  - `UI/` — Qt 6 startup flow, dialogs, main window, clipboard handling.
  - `vault_storage/` — `Vault`, serialization, `VaultDescriptor`/AAD,
    `SafeFileWriter`, `UnlockThrottle`.
  - `crypto_service/` — AEAD wrappers over libsodium.
  - `master_key_generator/` — Argon2id derivation, `Key`, `SecureString`,
    `EphemeralKey`, `EncryptedField`, salts and nonces.
  - `password_generator/` — policy-based password generator.
  - `process_hardening/` — Linux process hardening, applied before
    `sodium_init()` and before `QApplication`.
- There is **no network service, no sync, no browser extension, and no Android
  component in this repository**.
- Trust boundaries:
  - The vault file is **untrusted and attacker-mutable**; parsing,
    authentication, and error handling must be safe against crafted files.
  - The master password is a secret input; decrypted entry passwords live in
    process memory protected by a session key.
  - The local OS/user session is not fully trusted: keyloggers, root malware,
    physical access, and memory remanence are outside the implemented
    protections.

## Cryptographic design inventory

- **KDF:** Argon2id via libsodium `crypto_pwhash` in
  `vault_storage/vault_model.cpp` and `master_key_generator/ephemeralkey.cpp`.
  - The source uses `crypto_pwhash_OPSLIMIT_MODERATE`,
    `crypto_pwhash_MEMLIMIT_MODERATE`, and `crypto_pwhash_ALG_ARGON2ID13` from
    `master_key_generator/utils.h`.
  - With the libsodium headers used here, `OPSLIMIT_MODERATE` is `3`,
    `MEMLIMIT_MODERATE` is `268435456` bytes (256 MiB), and
    `crypto_pwhash_SALTBYTES` is `16`.
  - The declared KDF profile is validated against `kSupportedKdfProfiles`
    **before** any derivation; currently only the current Argon2id13 MODERATE
    profile is accepted.
- **Three independent salts:**
  - metadata salt (`meta_salt`);
  - master-key salt (`master_salt`);
  - ephemeral/session salt (`ephemeral_salt`).
  - Each is 16 bytes and generated with libsodium's CSPRNG.
- **Three keys:**
  - metadata key — encrypts the whole serialized entry set on disk;
  - master key — encrypts individual password fields on disk;
  - session key — protects decrypted passwords while they live in memory,
    derived with `crypto_kdf_derive_from_key` and context `PMSESS0`.
- **AEAD:**
  - default XChaCha20-Poly1305 IETF with a 24-byte nonce;
  - selectable ChaCha20-Poly1305 IETF with a 12-byte nonce;
  - nonces are generated randomly per encryption operation (vault-level nonce
    and per-entry nonces are fresh on every save);
  - in-memory session `EncryptedField` values stay on XChaCha20.
- **AAD:**
  - `vault::VaultDescriptor` is encoded as a fixed **36-byte little-endian**
    layout: version (`u32`), KDF algorithm (`u32`), KDF ops limit (`u64`), KDF
    mem limit (`u64`), salt algorithm (`u32`), nonce algorithm (`u32`), cipher
    algorithm (`u32`).
  - The AAD is the descriptor followed by the header: three 16-byte salts plus
    the vault nonce, i.e. **108 bytes** for XChaCha20 (24-byte nonce) or
    **96 bytes** for ChaCha20 (12-byte nonce).
  - v0 files use the legacy header-only AAD; v1/v2 bind the descriptor too.
- **Cipher dispatch:** on read, the vault nonce length alone selects the AEAD
  (`24` → XChaCha20, `12` → ChaCha20, otherwise `VaultCorrupted`). v2 algorithm
  ids must agree with each other and with the nonce length; v1 files must remain
  XChaCha20-only.
- **Error mapping:**
  - future version, unknown/unsupported KDF/algorithm ids, v1/v2 id mismatches
    → `VaultError::InvalidFormat`;
  - malformed salt/nonce/entry sizes, oversized files, parse failures,
    duplicate or empty IDs, too many entries → `VaultError::VaultCorrupted`;
  - AEAD authentication failure (wrong password or tampered ciphertext/AAD) →
    `VaultError::CryptoError`;
  - file open/I/O and KDF allocation failures map to `FileOpenFailed`,
    `IoError`, and `OutOfMemory`.
- The build links **system libsodium** (`-lsodium`), although `MODULE.bazel`
  also declares a `libsodium` bazel dependency. Verify the actual library
  version in your environment.

## Security controls already present

- **Unlock throttling** in `vault_storage/unlock_throttle.{h,cpp}`:
  - exponential backoff starting at 100 ms, capped at 30 s;
  - jitter of up to the base delay (100 ms by default) added to each delay;
  - success resets the failure counter;
  - the password is always derived and the magic ciphertext authenticated before
    the throttle records success/failure, so there is no success-leaking fast
    path.
- **Load-path throttling:** `Serializator::deserialize` records a failure on
  AEAD `CryptoError` and a success on a completed load.
  `Vault::UnlockAndReload` passes `password_already_verified=true` to avoid
  double-counting.
- **Rekey verification:** `Vault::SetPassword` verifies the old password through
  `deriveAndVerify` (constant-time compare + throttle) and reuses the verified
  key for re-encryption, with rollback on save failure.
- **Backup recovery:** `SafeFileWriter` keeps the previous file as
  `<path>.bak` (0600) before replacement. `Serializator::deserialize` falls back
  to it only for structural/open failures, **never** on `CryptoError` or
  `OutOfMemory`; after recovery `vault.path_` still points at the real file.
- **Atomic writes:** `SafeFileWriter::WriteAtomic` uses `mkstemp` → write loop
  (handles `EINTR`) → `fsync` → backup (`<path>.bak` via hard link or copy) →
  `rename` → directory `fsync`. Temp files are created with 0600; the backup is
  `chmod`-ed to 0600.
- **Filesystem checks:** the writer relies on `mkstemp` and `chmod(0600)`. There
  is **no explicit `O_NOFOLLOW` or `fstat` owner check** on the target path;
  symlink/TOCTOU behaviour is therefore in scope for testing.
- **Secure memory:** `SecureString` uses `sodium_malloc` (guard pages; its
  `mlock` is best-effort, as libsodium documents), is read-only at rest, and
  wipes with `sodium_memzero`; `Key` and `EphemeralKey` use
  `sodium_mlock`/`sodium_memzero`, are non-copyable, and fail closed on locking
  errors. Comparisons use constant-time `sodium_memcmp`.
- **Plaintext zeroization:** the decrypted inner protobuf buffer in `deserialize`
  is guarded by `ZeroizeOnExit`; per-entry plaintext is held in `SecureString`.
  Review remaining plaintext `std::string` buffers (for example the serialized
  entries buffer in `serialize`) as part of a memory-lifetime audit.
- **Process hardening:** `hardening::apply()` sets `RLIMIT_CORE = 0`,
  `PR_SET_DUMPABLE = 0`, and `mlockall(MCL_CURRENT | MCL_FUTURE)` before the UI
  starts. Native builds fail closed on any error; the container build keeps the
  first two fail-closed and treats `mlockall` as best-effort (warning + fallback
  to `MCL_CURRENT`).
- **Non-throwing vault API:** public `Vault` operations return `std::expected`
  and `VaultError`; crypto helpers throw internally and are caught at the vault
  boundary.
- **Size limits:** `MAX_VAULT_SIZE` 8 MiB, `MAX_ENTRIES` 1000, `MAX_TITLE_SIZE`
  512, `MAX_LOGIN_SIZE` 1024, `MAX_NOTES_SIZE` 2048,
  `MAX_PASSWORD_CIPHERTEXT_SIZE` 2048 (`master_key_generator/utils.h`).
- **Build hardening:** `-fstack-protector-strong`, `-fcf-protection=full`,
  `-fstack-clash-protection`, RELRO/NOW, non-exec stack; `--config=strict` and
  `--config=release` are defined in `.bazelrc`.

## Suggested focus areas for testers

- **Vault parser:** craft protobuf files with truncated fields, duplicate fields,
  huge varints, oversized entries, duplicate/empty UUIDs, too many entries,
  unsupported versions, mismatched KDF/algorithm ids, wrong nonce lengths, and
  invalid per-entry nonces. Check `ParseFromString` behaviour and every
  early-return path in `vault_storage/vault_serializer.cpp`.
- **AAD canonicalization and downgrade:** try changing version, KDF parameters,
  algorithm ids, salts, and nonce; confirm v1/v2 tampering becomes `CryptoError`
  and future versions become `InvalidFormat`. Try to reinterpret a v2 file as
  v1/v0 or vice versa.
- **KDF parameter abuse:** verify that a file cannot request unbounded
  memory/CPU and that `is_supported_kdf_profile` runs before `crypto_pwhash`.
  Test allocation-failure handling and repeated-attempt DoS within an isolated
  environment.
- **Unlock throttling:** check bypasses across process restarts (the counter is
  in-memory per `Vault`), load-path accounting, `.bak` retry paths,
  `UnlockAndReload`'s `password_already_verified` flag, multiple processes, and
  UI retry loops. Argon2 runs before the throttle delay, so timing observations
  are expected.
- **`.bak` semantics:** verify fallback triggers, recovery when the main file is
  truncated or malformed, permissions, `path_` after recovery, and the fact that
  after a rekey the `.bak` contains the pre-rekey vault encrypted with the old
  password.
- **Filesystem and TOCTOU:** inspect temp-file naming
  (`<target>.tmp.<pid>.XXXXXX`), backup staging (`<path>.bak.tmp.<pid>`), symlink
  targets, hard-link behavior, target-path permissions, leftover temp files, and
  directory `fsync` failure handling.
- **Secret lifetime and copies:** trace master passwords and decrypted entries
  through `SecureString`, `QString`, `QByteArray`, `std::string`, and protobuf
  buffers. Check clipboard auto-clear (30 s) and its fingerprint logic,
  show-password behaviour, and `Lock()` metadata wiping.
- **UI behaviour:** error messages from `describe()`, file-dialog paths,
  `Lock`/unlock flow, quit-on-cancel, lack of autolock, and UI freezes during
  Argon2. The stylesheet is loaded from the compiled Qt resource `:/dark.qss`
  via `qt_qrc`/`qt_cc_rcc`.
- **Memory safety:** run the parser and crypto tests under ASan/UBSan and
  attempt fuzzing of `Serializator::deserialize` with crafted vault files.
- **Supply chain:** review `MODULE.bazel` (protobuf, Qt `git_override`, declared
  libsodium dependency) and confirm which system libraries are actually linked.

## Known limitations and explicit non-goals

- No independent security audit, no fuzzing target yet, and no CI.
- Argon2 currently blocks the Qt event loop during
  create/unlock/load/save/rekey.
- Autolock on idle/suspend is **not implemented**.
- UI for `SetPassword` (rekey) and `SetNotes` is missing; the C++ API exists.
- Changing the cipher of an existing vault is not exposed in the UI; cipher
  selection happens at creation, and the open file's cipher is shown read-only.
- The `.bak` after a rekey is the pre-rekey file encrypted with the **old**
  password. It is a local recovery artifact, not a revocation mechanism.
- No protection against OS compromise, keyloggers, root malware, malicious
  dependencies, physical access, cold-boot attacks, or SSD remanence.
- No secure deletion of vault files or backups.
- No network service, sync, TOTP/2FA, or import/export yet.
- The unlock throttle is in-memory and resets when the process restarts; there is
  no persistent lockout.
- No supported-version matrix and no formal threat-model document yet.

## Build, run, and instrumentation

Prerequisites: a C++23 compiler, Bazel/Bazelisk, Qt 6 development files, system
libsodium, and the dependencies declared in `MODULE.bazel`. The build is
Bazel + Bzlmod only; there is no CMake or Makefile, and WORKSPACE mode is
disabled (`--noenable_workspace` in `.bazelrc`).

```bash
bazelisk build //...
bazelisk build //UI:UI
bazelisk test //...
bazelisk test //vault_storage/tests:vault_test
```

Instrumented builds and tests:

```bash
bazelisk build --config=asan //...
bazelisk build --config=ubsan //...          # also enables ASan per .bazelrc
bazelisk test --config=asan //...
bazelisk test --config=ubsan //...
bazelisk build --config=strict //...          # -Wall -Wextra -Werror -Wshadow on first-party code
bazelisk build --config=release -c opt //...  # _FORTIFY_SOURCE=2, NDEBUG
```

Run the real application:

```bash
bazelisk run //UI:UI
```

The Qt form tests run offscreen via the `QT_QPA_PLATFORM=offscreen` environment
set in `UI/tests/BUILD`:

```bash
bazelisk test //UI/tests:ui_test
```

If Bazel's default sandbox fails in your environment, append
`--spawn_strategy=local` to the command. To regenerate `compile_commands.json`,
use `./generate_compile_commands.sh` (it builds through a temporary WORKSPACE to
avoid the Bzlmod conflict with `hedron_compile_commands`).

## Safe testing setup

- Work in a temporary directory, for example `mktemp -d`.
- Create test vaults there with dummy passwords; never use real credentials.
- Expect artifacts such as `*.vault`, `*.vault.bak`, `*.tmp.<pid>.*`, and legacy
  `*.bin`, `*.nonce`, `salt.bin` files.
- `.gitignore` already covers `*.bin`, `*.nonce`, `salt.bin`, and `vault.bin`;
  never commit test vaults, backups, or generated secrets.
- Copy any existing vault before testing; do not run destructive tests against
  the only copy.
- Do not send vault contents, passwords, keys, or derived material to external
  services.

## Further reading

- `README.md` — features, architecture, format v2, build and test commands.
- `CONTRIBUTING.md` — coding rules, secure-memory guidance, testing rules, and
  vulnerability-disclosure expectations.
- `PLAN.md` — completed hardening work, roadmap, and known gaps.
- `AGENTS.md` — build/test gotchas, vault-format invariants, and repo
  conventions.

`CONTRIBUTING.md` treats cryptographic changes as discussion-first: do not add
custom primitives, and do not change encryption algorithms, key derivation,
salts, nonces, authentication, key hierarchy, vault file format, encryption
order, password verification, or secure-memory handling without an
architectural/security discussion.
