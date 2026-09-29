#pragma once
#include <exception>
#include <iostream>
#include <string>

// Shared counters and assertions for the test programs. Each program keeps its
// own summary line and exit status, because each reports a different suite.
namespace armflow_tests {
inline unsigned passed = 0;
inline unsigned failed = 0;

inline void check(bool condition, const std::string &name) {
  if (condition)
    ++passed;
  else {
    ++failed;
    std::cerr << "FAIL: " << name << '\n';
  }
}

// Passes when the action throws. A test that expects a refusal must not pass
// merely because the call returned something. Name the exception type where the
// refusal is part of the contract, so an unrelated failure cannot satisfy it.
template <class Expected = std::exception, class Action>
void rejects(Action action, const std::string &name) {
  try {
    action();
    check(false, name);
  } catch (const Expected &) {
    check(true, name);
  }
}
} // namespace armflow_tests
