#include "process_hardening.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>

namespace hardening {
namespace {

[[noreturn]] void fail(const char *step, const char *reason) {
  throw std::runtime_error{std::string{step} + ": " + reason};
}

#ifdef PM_CONTAINER_BUILD

std::string memlock_limit_text() {
  struct rlimit limit{};
  if (getrlimit(RLIMIT_MEMLOCK, &limit) == -1)
    return "unknown";
  if (limit.rlim_cur == RLIM_INFINITY)
    return "unlimited";
  return std::to_string(static_cast<unsigned long long>(limit.rlim_cur));
}

// Emits at most one container-mode warning per process.
void warn_once(const std::string &message) {
  static bool warned = false;
  if (warned)
    return;
  warned = true;
  std::fprintf(stderr, "%s\n", message.c_str());
}

// Container builds run under Docker's default RLIMIT_MEMLOCK, where a full
// mlockall() commonly fails. Locking is best-effort here, but we degrade
// loudly: first try to lock current + future pages, then only current pages,
// and finally warn instead of aborting startup.
void lock_memory_best_effort() {
  if (mlockall(MCL_CURRENT | MCL_FUTURE) == 0)
    return;

  // Copy the strerror() result before the next call reuses its static buffer.
  const int future_errno = errno;
  const std::string future_reason = std::strerror(future_errno);

  if (mlockall(MCL_CURRENT) == 0) {
    warn_once("Warning: mlockall(MCL_FUTURE) failed in container build "
              "(MCL_CURRENT|MCL_FUTURE: " +
              future_reason + ", RLIMIT_MEMLOCK=" + memlock_limit_text() +
              "); only current pages are locked. Run with --ulimit "
              "memlock=-1 for full hardening.");
    return;
  }

  const int current_errno = errno;
  const std::string current_reason = std::strerror(current_errno);

  warn_once("Warning: mlockall failed in container build "
            "(MCL_CURRENT|MCL_FUTURE: " +
            future_reason + ", MCL_CURRENT: " + current_reason +
            ", RLIMIT_MEMLOCK=" + memlock_limit_text() +
            "); secrets may be swapped. Run with --ulimit memlock=-1 for "
            "full hardening.");
}

#else

// Default build: locking is mandatory.
void lock_memory_strict() {
  if (mlockall(MCL_CURRENT | MCL_FUTURE) == -1)
    fail("mlockall", std::strerror(errno));
}

#endif

} // namespace

void apply() {
  struct rlimit core_limit{0, 0};
  if (setrlimit(RLIMIT_CORE, &core_limit) == -1)
    fail("RLIMIT_CORE", std::strerror(errno));

  if (prctl(PR_SET_DUMPABLE, 0) == -1)
    fail("PR_SET_DUMPABLE", std::strerror(errno));

#ifdef PM_CONTAINER_BUILD
  lock_memory_best_effort();
#else
  lock_memory_strict();
#endif
}

} // namespace hardening
