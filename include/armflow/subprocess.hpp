#pragma once
#include <armflow/binary_image.hpp>
namespace armflow {
struct CommandOutcome {
  int exit_code = 0;
  ByteBuffer output, errors;
};
// Every subprocess this product starts shares one timeout range and default.
// Callers validate the configured value before spawning so they can name the
// setting that is wrong, which only helps if they check the range spawn_process
// itself enforces.
inline constexpr unsigned default_process_timeout_milliseconds = 30000;
inline constexpr unsigned maximum_process_timeout_milliseconds = 60000;
CommandOutcome spawn_process(
    const std::vector<std::string> &arguments,
    std::span<const std::uint8_t> input,
    unsigned timeout_milliseconds = default_process_timeout_milliseconds,
    std::size_t maximum_output = 8 * 1024 * 1024);
class ScratchDirectory {
public:
  ScratchDirectory();
  ~ScratchDirectory();
  ScratchDirectory(const ScratchDirectory &) = delete;
  ScratchDirectory &operator=(const ScratchDirectory &) = delete;
  const std::filesystem::path &path() const { return path_; }

private:
  std::filesystem::path path_;
};
} // namespace armflow
