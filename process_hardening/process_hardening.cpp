#include "process_hardening.h"

#include <cerrno>
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

} // namespace

void apply() {
  struct rlimit core_limit{0, 0};
  if (setrlimit(RLIMIT_CORE, &core_limit) == -1)
    fail("RLIMIT_CORE", std::strerror(errno));

  if (prctl(PR_SET_DUMPABLE, 0) == -1)
    fail("PR_SET_DUMPABLE", std::strerror(errno));

  if (mlockall(MCL_CURRENT | MCL_FUTURE) == -1)
    fail("mlockall", std::strerror(errno));
}

} // namespace hardening