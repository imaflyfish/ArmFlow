#pragma once
#include <cstdint>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace armflow {
using Address = std::uint64_t;
using ByteBuffer = std::vector<std::uint8_t>;
using JsonDoc = nlohmann::ordered_json;
struct FlowError : std::runtime_error {
  using std::runtime_error::runtime_error;
};
std::string format_address(Address value);
Address address_of_json(const JsonDoc &value);
ByteBuffer bytes_of_hex(const std::string &value);
std::string hex_of_bytes(std::span<const std::uint8_t> value);
std::string sha256_hex(std::span<const std::uint8_t> bytes);
ByteBuffer load_file(const std::filesystem::path &path,
                    std::size_t cap = 256 * 1024 * 1024);
JsonDoc document_of_bytes(std::span<const std::uint8_t> bytes);
JsonDoc load_document(const std::filesystem::path &path);
void store_document(const std::filesystem::path &path, const JsonDoc &value);

struct ImageRegion {
  Address begin = 0;
  ByteBuffer bytes;
  std::string label;
  bool readable = true, writable = false, executable = false;
  std::optional<std::uint64_t> source_offset;
  Address end() const;
  bool contains(Address address, std::size_t length = 1) const;
};
struct RoutineSpan {
  Address begin = 0, end = 0;
  std::string label;
};
struct FlowEdge {
  Address source = 0, target = 0;
  bool owned = false;
};
class BinaryImage {
public:
  std::vector<ImageRegion> regions;
  std::vector<RoutineSpan> functions;
  std::vector<FlowEdge> references;
  Address entry = 0;
  bool relocated = false;
  std::string origin;
  void validate() const;
  const ImageRegion *region_at(Address address, std::size_t length = 1) const;
  const RoutineSpan *function_at(Address address) const;
  std::optional<std::uint64_t> integer(Address address, unsigned width) const;
  std::optional<std::uint32_t> instruction(Address address) const;
  ByteBuffer read(Address address, std::size_t length) const;
  void replace(Address address, std::span<const std::uint8_t> bytes);
  bool valid_target(Address address) const;
  std::string fingerprint() const;
  JsonDoc snapshot() const;
  static BinaryImage from_snapshot(const JsonDoc &document);
  static BinaryImage from_elf(std::span<const std::uint8_t> file);
  static BinaryImage from_flat(std::span<const std::uint8_t> file,
                             const JsonDoc &mapping);
  static BinaryImage load(const std::filesystem::path &path);
};
} // namespace armflow
