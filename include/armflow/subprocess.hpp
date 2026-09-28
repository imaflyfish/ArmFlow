#pragma once
#include <armflow/binary_image.hpp>
namespace armflow {
struct CommandOutcome {
  int exit_code = 0;
  ByteBuffer output, errors;
};
CommandOutcome spawn_process(const std::vector<std::string> &arguments,
                          std::span<const std::uint8_t> input,
                          unsigned timeout_milliseconds = 30000,
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
