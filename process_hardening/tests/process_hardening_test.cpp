#include "process_hardening/process_hardening.h"

#include <fstream>
#include <string>
#include <sys/prctl.h>
#include <sys/resource.h>

#include <gtest/gtest.h>

namespace {

class ProcessHardeningTest : public ::testing::Test {
protected:
  static void SetUpTestSuite() { hardening::apply(); }
};

TEST_F(ProcessHardeningTest, DumpsAreImpossible) {
  struct rlimit core;
  ASSERT_EQ(getrlimit(RLIMIT_CORE, &core), 0);
  EXPECT_EQ(core.rlim_cur, 0u);
  EXPECT_EQ(core.rlim_max, 0u);
}

TEST_F(ProcessHardeningTest, ProcessIsNotDumpable) {
  EXPECT_EQ(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0), 0);
}

TEST_F(ProcessHardeningTest, MemoryIsLocked) {
  std::ifstream status("/proc/self/status");
  ASSERT_TRUE(status.is_open());

  std::string line;
  unsigned long vm_locked = 0;
  while (std::getline(status, line)) {
    if (line.rfind("VmLck:", 0) == 0)
      vm_locked = std::stoul(line.substr(line.find(':') + 1));
  }

  EXPECT_GT(vm_locked, 0ul) << "mlockall pinned no resident pages";
}

} // namespace