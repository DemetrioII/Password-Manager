#include "process_hardening/process_hardening.h"

#include <sys/prctl.h>
#include <sys/resource.h>

#include <gtest/gtest.h>

namespace {

// Container builds must still apply the cheap, always-available protections
// even when mlockall() cannot succeed under Docker's default RLIMIT_MEMLOCK.
TEST(ProcessHardeningContainerTest, ApplySucceedsWithoutMemlock) {
  struct rlimit memlock{0, 0};
  ASSERT_EQ(setrlimit(RLIMIT_MEMLOCK, &memlock), 0);

  EXPECT_NO_THROW(hardening::apply());

  struct rlimit core;
  ASSERT_EQ(getrlimit(RLIMIT_CORE, &core), 0);
  EXPECT_EQ(core.rlim_cur, 0u);
  EXPECT_EQ(core.rlim_max, 0u);

  EXPECT_EQ(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0), 0);
}

} // namespace
