#include <armflow/subprocess.hpp>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
namespace armflow {
namespace {
struct FileDescriptor {
  int value = -1;
  FileDescriptor() = default;
  explicit FileDescriptor(int supplied) : value(supplied) {}
  ~FileDescriptor() {
    if (value >= 0)
      ::close(value);
  }
  FileDescriptor(const FileDescriptor &) = delete;
  FileDescriptor &operator=(const FileDescriptor &) = delete;
  void close() {
    if (value >= 0) {
      ::close(value);
      value = -1;
    }
  }
};
void nonblocking(int descriptor) {
  auto flags = fcntl(descriptor, F_GETFL);
  if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) < 0)
    throw FlowError("cannot set nonblocking process stream");
}
void close_on_exec(int descriptor) {
  if (fcntl(descriptor, F_SETFD, FD_CLOEXEC) < 0)
    throw FlowError("cannot protect process descriptor");
}
struct ChildProcess {
  pid_t pid = -1;
  bool reaped = false;
  ~ChildProcess() {
    if (pid > 0) {
      kill(-pid, SIGKILL);
      if (!reaped)
        while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {
        }
    }
  }
};
} // namespace
ScratchDirectory::ScratchDirectory() {
  auto pattern =
      (std::filesystem::temp_directory_path() / "armflow-XXXXXX").string();
  std::vector<char> buffer(pattern.begin(), pattern.end());
  buffer.push_back(0);
  auto created = mkdtemp(buffer.data());
  if (!created)
    throw FlowError("cannot create private temporary directory");
  path_ = created;
}
ScratchDirectory::~ScratchDirectory() {
  std::error_code ignored;
  std::filesystem::remove_all(path_, ignored);
}
CommandOutcome spawn_process(const std::vector<std::string> &arguments,
                          std::span<const std::uint8_t> input,
                          unsigned timeout_milliseconds,
                          std::size_t maximum_output) {
  if (arguments.empty() || arguments.size() > 256 || arguments[0].empty() ||
      timeout_milliseconds == 0 || timeout_milliseconds > 60000 ||
      maximum_output == 0 || maximum_output > 64 * 1024 * 1024 ||
      input.size() > 64 * 1024 * 1024)
    throw FlowError("invalid process request limits");
  for (const auto &argument : arguments)
    if (argument.size() > 1024 * 1024 ||
        argument.find('\0') != std::string::npos)
      throw FlowError("invalid process argument");
  int input_pair[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, input_pair) < 0)
    throw FlowError("cannot create child input stream");
  FileDescriptor input_parent(input_pair[0]), input_child(input_pair[1]);
  int output_pair[2];
  if (pipe(output_pair) < 0)
    throw FlowError("cannot create child output stream");
  FileDescriptor output_parent(output_pair[0]), output_child(output_pair[1]);
  int error_pair[2];
  if (pipe(error_pair) < 0)
    throw FlowError("cannot create child error stream");
  FileDescriptor error_parent(error_pair[0]), error_child(error_pair[1]);
  for (auto descriptor :
       {input_parent.value, input_child.value, output_parent.value,
        output_child.value, error_parent.value, error_child.value})
    close_on_exec(descriptor);
  nonblocking(input_parent.value);
  nonblocking(output_parent.value);
  nonblocking(error_parent.value);
#ifdef SO_NOSIGPIPE
  int suppress = 1;
  if (setsockopt(input_parent.value, SOL_SOCKET, SO_NOSIGPIPE, &suppress,
                 sizeof(suppress)) < 0)
    throw FlowError("cannot suppress stream SIGPIPE");
#endif
  posix_spawn_file_actions_t actions;
  posix_spawnattr_t attributes;
  if (posix_spawn_file_actions_init(&actions) != 0)
    throw FlowError("cannot initialize spawn actions");
  if (posix_spawnattr_init(&attributes) != 0) {
    posix_spawn_file_actions_destroy(&actions);
    throw FlowError("cannot initialize spawn attributes");
  }
  auto action_error = posix_spawn_file_actions_adddup2(
      &actions, input_child.value, STDIN_FILENO);
  action_error |= posix_spawn_file_actions_adddup2(&actions, output_child.value,
                                                   STDOUT_FILENO);
  action_error |= posix_spawn_file_actions_adddup2(&actions, error_child.value,
                                                   STDERR_FILENO);
  action_error |= posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP);
  action_error |= posix_spawnattr_setpgroup(&attributes, 0);
  std::vector<char *> argv;
  for (const auto &argument : arguments)
    argv.push_back(const_cast<char *>(argument.c_str()));
  argv.push_back(nullptr);
  ChildProcess child;
  auto status = action_error ? EINVAL
                             : posix_spawnp(&child.pid, argv[0], &actions,
                                            &attributes, argv.data(), environ);
  posix_spawn_file_actions_destroy(&actions);
  posix_spawnattr_destroy(&attributes);
  if (status) {
    child.pid = -1;
    throw FlowError("cannot launch process: " +
                        std::string(strerror(status)));
  }
  input_child.close();
  output_child.close();
  error_child.close();
  CommandOutcome result;
  std::size_t sent = 0;
  int child_status = 0;
  auto deadline = std::chrono::steady_clock::now() +
                  std::chrono::milliseconds(timeout_milliseconds);
  auto drain = [&](FileDescriptor &descriptor, ByteBuffer &destination) {
    if (descriptor.value < 0)
      return;
    std::array<std::uint8_t, 8192> buffer{};
    for (;;) {
      auto count = read(descriptor.value, buffer.data(), buffer.size());
      if (count > 0) {
        auto size = static_cast<std::size_t>(count);
        if (size > maximum_output - destination.size())
          throw FlowError("process output limit exceeded");
        destination.insert(destination.end(), buffer.begin(),
                           buffer.begin() + count);
      } else if (count == 0) {
        descriptor.close();
        return;
      } else if (errno == EINTR)
        continue;
      else if (errno == EAGAIN || errno == EWOULDBLOCK)
        return;
      else
        throw FlowError("failed to read child output");
    }
  };
  while (!child.reaped || output_parent.value >= 0 || error_parent.value >= 0) {
    if (std::chrono::steady_clock::now() >= deadline)
      throw FlowError("process execution timed out");
    if (sent == input.size() && input_parent.value >= 0) {
      shutdown(input_parent.value, SHUT_WR);
      input_parent.close();
    }
    pollfd descriptors[3] = {{output_parent.value, POLLIN, 0},
                             {error_parent.value, POLLIN, 0},
                             {input_parent.value, POLLOUT, 0}};
    auto ready = poll(descriptors, 3, 10);
    if (ready < 0 && errno != EINTR)
      throw FlowError("process stream polling failed");
    if (input_parent.value >= 0 &&
        (descriptors[2].revents & (POLLOUT | POLLERR | POLLHUP))) {
      int flags = 0;
#ifdef MSG_NOSIGNAL
      flags = MSG_NOSIGNAL;
#endif
      auto count =
          send(input_parent.value, input.data() + sent,
               std::min<std::size_t>(input.size() - sent, 65536), flags);
      if (count > 0)
        sent += static_cast<std::size_t>(count);
      else if (count < 0 && (errno == EPIPE || errno == ECONNRESET))
        input_parent.close();
      else if (count < 0 && errno != EINTR && errno != EAGAIN &&
               errno != EWOULDBLOCK)
        throw FlowError("failed to write child input");
    }
    drain(output_parent, result.output);
    drain(error_parent, result.errors);
    if (!child.reaped) {
      auto ended = waitpid(child.pid, &child_status, WNOHANG);
      if (ended == child.pid)
        child.reaped = true;
      else if (ended < 0 && errno != EINTR)
        throw FlowError("failed to collect child status");
    }
  }
  result.exit_code =
      WIFEXITED(child_status)
          ? WEXITSTATUS(child_status)
          : 128 + (WIFSIGNALED(child_status) ? WTERMSIG(child_status) : 0);
  return result;
}
} // namespace armflow
