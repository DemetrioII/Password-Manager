#pragma once

namespace hardening {
// Locks the process down against core dumps, external ptrace and swap.
// Call once, first thing in main(). Throws std::runtime_error on failure.
void apply();
} // namespace hardening