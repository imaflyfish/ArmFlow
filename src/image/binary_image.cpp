#include <armflow/binary_image.hpp>
#include <algorithm>
#include <cerrno>
#include <charconv>
#include <fstream>
#include <gcrypt.h>
#include <iomanip>
#include <limits>
#include <memory>
#include <set>
#include <sstream>
#include <unistd.h>
#include <yaml-cpp/yaml.h>
namespace armflow {
namespace {
constexpr std::size_t maximum_image = 256 * 1024 * 1024;
std::uint64_t little(std::span<const std::uint8_t> view, std::uint64_t offset,
                     unsigned width) {
  if (width == 0 || width > 8 || offset > view.size() ||
      width > view.size() - offset)
    throw FlowError("integer extends beyond its input");
  std::uint64_t value = 0;
  for (unsigned index = 0; index < width; ++index)
    value |= std::uint64_t(view[static_cast<std::size_t>(offset) + index])
             << (index * 8);
  return value;
}
std::span<const std::uint8_t> range(std::span<const std::uint8_t> view,
                                    std::uint64_t offset,
                                    std::uint64_t length) {
  if (offset > view.size() || length > view.size() - offset)
    throw FlowError("ELF range extends beyond the file");
  return view.subspan(static_cast<std::size_t>(offset),
                      static_cast<std::size_t>(length));
}
std::string terminated(std::span<const std::uint8_t> view,
                       std::uint64_t offset) {
  if (offset >= view.size())
    throw FlowError("string offset exceeds its table");
  auto start = view.begin() + static_cast<std::ptrdiff_t>(offset);
  auto finish = std::find(start, view.end(), 0);
  if (finish == view.end())
    throw FlowError("unterminated ELF string");
  return {start, finish};
}
JsonDoc yaml_value(const YAML::Node &node, std::size_t &remaining,
                unsigned depth = 0) {
  if (remaining == 0)
    throw FlowError("YAML node limit exceeded");
  --remaining;
  if (depth > 40)
    throw FlowError("YAML nesting limit exceeded");
  if (node.IsNull())
    return nullptr;
  if (node.IsSequence()) {
    JsonDoc result = JsonDoc::array();
    if (node.size() > 100000)
      throw FlowError("YAML array limit exceeded");
    for (const auto &value : node)
      result.push_back(yaml_value(value, remaining, depth + 1));
    return result;
  }
  if (node.IsMap()) {
    JsonDoc result = JsonDoc::object();
    for (const auto &entry : node) {
      auto key = entry.first.as<std::string>();
      if (result.contains(key))
        throw FlowError("duplicate YAML key");
      result[key] = yaml_value(entry.second, remaining, depth + 1);
    }
    return result;
  }
  if (!node.IsScalar())
    throw FlowError("unsupported YAML value");
  auto text = node.Scalar();
  if (node.Tag() == "!")
    return text;
  if (text == "true" || text == "True" || text == "TRUE")
    return true;
  if (text == "false" || text == "False" || text == "FALSE")
    return false;
  if (text == "null" || text == "~")
    return nullptr;
  std::int64_t signed_value = 0;
  auto signed_result =
      std::from_chars(text.data(), text.data() + text.size(), signed_value);
  if (signed_result.ec == std::errc{} &&
      signed_result.ptr == text.data() + text.size())
    return signed_value;
  if (text.starts_with("0x"))
    return address_of_json(JsonDoc(text));
  return text;
}
} // namespace
std::string format_address(Address value) {
  std::ostringstream output;
  output << "0x" << std::hex << value;
  return output.str();
}
Address address_of_json(const JsonDoc &value) {
  if (value.is_number_unsigned())
    return value.get<Address>();
  if (value.is_number_integer()) {
    auto number = value.get<std::int64_t>();
    if (number < 0)
      throw FlowError("negative address");
    return static_cast<Address>(number);
  }
  if (!value.is_string())
    throw FlowError("address must be an integer or a string");
  auto text = value.get<std::string>();
  int base = 10;
  std::size_t prefix = 0;
  if (text.starts_with("0x") || text.starts_with("0X")) {
    base = 16;
    prefix = 2;
  }
  Address result = 0;
  auto parsed = std::from_chars(text.data() + prefix, text.data() + text.size(),
                                result, base);
  if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
      prefix == text.size())
    throw FlowError("invalid address: " + text);
  return result;
}
ByteBuffer bytes_of_hex(const std::string &value) {
  if (value.size() % 2)
    throw FlowError("hex input must have an even length");
  if (value.size() > maximum_image * 2)
    throw FlowError("hex input size limit exceeded");
  ByteBuffer result;
  result.reserve(value.size() / 2);
  for (std::size_t offset = 0; offset < value.size(); offset += 2) {
    unsigned byte = 0;
    auto parsed = std::from_chars(value.data() + offset,
                                  value.data() + offset + 2, byte, 16);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + offset + 2)
      throw FlowError("invalid hex input");
    result.push_back(static_cast<std::uint8_t>(byte));
  }
  return result;
}
std::string hex_of_bytes(std::span<const std::uint8_t> value) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(value.size() * 2);
  for (auto byte : value) {
    result.push_back(digits[byte >> 4]);
    result.push_back(digits[byte & 15]);
  }
  return result;
}
std::string sha256_hex(std::span<const std::uint8_t> bytes) {
  std::uint8_t digest[32];
  static const bool available = gcry_check_version("1.10.0") != nullptr;
  if (!available)
    throw FlowError("libgcrypt initialization failed");
  gcry_md_hash_buffer(GCRY_MD_SHA256, digest, bytes.data(), bytes.size());
  return hex_of_bytes(digest);
}
ByteBuffer load_file(const std::filesystem::path &path, std::size_t cap) {
  if (!std::filesystem::is_regular_file(path))
    throw FlowError("not a regular file: " + path.string());
  auto size = std::filesystem::file_size(path);
  if (size > cap)
    throw FlowError("file size limit exceeded");
  std::ifstream input(path, std::ios::binary);
  ByteBuffer bytes(static_cast<std::size_t>(size));
  if (!input || !input.read(reinterpret_cast<char *>(bytes.data()),
                            static_cast<std::streamsize>(bytes.size())))
    throw FlowError("cannot read file: " + path.string());
  if (input.peek() != std::char_traits<char>::eof())
    throw FlowError("file changed during reading");
  return bytes;
}
JsonDoc load_document(const std::filesystem::path &path) {
  auto bytes = load_file(path, maximum_image * 2);
  try {
    if (path.extension() == ".yml" || path.extension() == ".yaml") {
      std::size_t remaining = 1000000;
      return yaml_value(YAML::Load(std::string(bytes.begin(), bytes.end())),
                        remaining);
    }
    return document_of_bytes(bytes);
  } catch (const std::exception &error) {
    throw FlowError("invalid document: " + std::string(error.what()));
  }
}
JsonDoc document_of_bytes(std::span<const std::uint8_t> bytes) {
  if (bytes.size() > maximum_image * 2)
    throw FlowError("document size limit exceeded");
  std::vector<std::set<std::string>> keys(65);
  std::size_t events = 0;
  return JsonDoc::parse(bytes.begin(), bytes.end(),
                     [&](int depth, JsonDoc::parse_event_t event, JsonDoc &value) {
                       if (depth < 0 || depth > 64 || ++events > 4000000)
                         throw FlowError("JSON structural limit exceeded");
                       if (event == JsonDoc::parse_event_t::object_start)
                         keys[static_cast<std::size_t>(depth)].clear();
                       if (event == JsonDoc::parse_event_t::key) {
                         if (depth < 1 ||
                             !keys[static_cast<std::size_t>(depth - 1)]
                                  .insert(value.get<std::string>())
                                  .second)
                           throw FlowError("duplicate JSON key");
                       }
                       return true;
                     });
}
void store_document(const std::filesystem::path &path, const JsonDoc &value) {
  auto parent = path.parent_path().empty() ? std::filesystem::path(".")
                                           : path.parent_path();
  std::filesystem::create_directories(parent);
  auto pattern = (parent / ".armflow-write-XXXXXX").string();
  std::vector<char> name(pattern.begin(), pattern.end());
  name.push_back(0);
  int descriptor = mkstemp(name.data());
  if (descriptor < 0)
    throw FlowError("cannot create temporary output file");
  try {
    auto text = value.dump(2) + "\n";
    std::size_t offset = 0;
    while (offset < text.size()) {
      auto count =
          ::write(descriptor, text.data() + offset, text.size() - offset);
      if (count < 0 && errno == EINTR)
        continue;
      if (count <= 0)
        throw FlowError("cannot write output document");
      offset += static_cast<std::size_t>(count);
    }
    if (fsync(descriptor) < 0)
      throw FlowError("cannot sync output document");
    if (::close(descriptor) < 0) {
      descriptor = -1;
      throw FlowError("cannot close output document");
    }
    descriptor = -1;
    if (::rename(name.data(), path.c_str()) < 0)
      throw FlowError("cannot replace output document");
  } catch (...) {
    if (descriptor >= 0)
      ::close(descriptor);
    ::unlink(name.data());
    throw;
  }
}
Address ImageRegion::end() const {
  if (bytes.size() > std::numeric_limits<Address>::max() - begin)
    throw FlowError("memory region address overflow");
  return begin + bytes.size();
}
bool ImageRegion::contains(Address address, std::size_t length) const {
  return address >= begin && address <= end() && length <= end() - address;
}
void BinaryImage::validate() const {
  if (regions.empty() || regions.size() > 4096)
    throw FlowError("image requires 1..4096 memory regions");
  std::size_t total = 0;
  std::vector<const ImageRegion *> ordered;
  for (const auto &region : regions) {
    if (region.bytes.empty() || region.bytes.size() > maximum_image - total)
      throw FlowError("invalid or excessive memory region size");
    total += region.bytes.size();
    (void)region.end();
    ordered.push_back(&region);
  }
  std::sort(ordered.begin(), ordered.end(),
            [](auto left, auto right) { return left->begin < right->begin; });
  for (std::size_t index = 1; index < ordered.size(); ++index)
    if (ordered[index]->begin < ordered[index - 1]->end())
      throw FlowError("overlapping memory regions");
  if (functions.size() > 1000000 || references.size() > 2000000)
    throw FlowError("image metadata count limit exceeded");
  for (const auto &function : functions) {
    if (function.begin >= function.end || function.begin % 4 ||
        function.end % 4 ||
        !region_at(function.begin,
                   static_cast<std::size_t>(function.end - function.begin)))
      throw FlowError("invalid function bounds");
  }
}
const ImageRegion *BinaryImage::region_at(Address address,
                                         std::size_t length) const {
  for (const auto &region : regions)
    if (region.contains(address, length))
      return &region;
  return nullptr;
}
const RoutineSpan *BinaryImage::function_at(Address address) const {
  for (const auto &function : functions)
    if (address >= function.begin && address < function.end)
      return &function;
  return nullptr;
}
std::optional<std::uint64_t> BinaryImage::integer(Address address,
                                                unsigned width) const {
  auto region = region_at(address, width);
  if (!region || width == 0 || width > 8)
    return {};
  return little(region->bytes, address - region->begin, width);
}
std::optional<std::uint32_t> BinaryImage::instruction(Address address) const {
  if (address % 4)
    return {};
  auto region = region_at(address, 4);
  if (!region || !region->executable)
    return {};
  return static_cast<std::uint32_t>(*integer(address, 4));
}
ByteBuffer BinaryImage::read(Address address, std::size_t length) const {
  auto region = region_at(address, length);
  if (!region)
    throw FlowError("unmapped read at " + format_address(address));
  auto offset = static_cast<std::size_t>(address - region->begin);
  return {region->bytes.begin() + static_cast<std::ptrdiff_t>(offset),
          region->bytes.begin() + static_cast<std::ptrdiff_t>(offset + length)};
}
void BinaryImage::replace(Address address, std::span<const std::uint8_t> bytes) {
  for (auto &region : regions)
    if (region.contains(address, bytes.size())) {
      std::copy(bytes.begin(), bytes.end(),
                region.bytes.begin() +
                    static_cast<std::ptrdiff_t>(address - region.begin));
      return;
    }
  throw FlowError("unmapped write");
}
bool BinaryImage::valid_target(Address address) const {
  return address != 0 && address != std::numeric_limits<Address>::max() &&
         instruction(address).has_value();
}
JsonDoc BinaryImage::snapshot() const {
  JsonDoc result = {{"schema_version", 1},
                 {"architecture", "aarch64"},
                 {"entry", format_address(entry)},
                 {"relocated", relocated},
                 {"origin", origin},
                 {"regions", JsonDoc::array()},
                 {"functions", JsonDoc::array()},
                 {"references", JsonDoc::array()}};
  for (const auto &region : regions)
    result["regions"].push_back(
        {{"begin", format_address(region.begin)},
         {"bytes", hex_of_bytes(region.bytes)},
         {"label", region.label},
         {"readable", region.readable},
         {"writable", region.writable},
         {"executable", region.executable},
         {"source_offset",
          region.source_offset ? JsonDoc(*region.source_offset) : JsonDoc(nullptr)}});
  for (const auto &function : functions)
    result["functions"].push_back({{"begin", format_address(function.begin)},
                                   {"end", format_address(function.end)},
                                   {"label", function.label}});
  for (const auto &reference : references)
    result["references"].push_back({{"source", format_address(reference.source)},
                                    {"target", format_address(reference.target)},
                                    {"owned", reference.owned}});
  return result;
}
std::string BinaryImage::fingerprint() const {
  auto document = snapshot();
  document.erase("origin");
  auto serialized = document.dump();
  return sha256_hex({reinterpret_cast<const std::uint8_t *>(serialized.data()),
                 serialized.size()});
}
BinaryImage BinaryImage::from_snapshot(const JsonDoc &document) {
  if (document.at("schema_version") != 1 ||
      document.at("architecture") != "aarch64")
    throw FlowError("unsupported snapshot version or architecture");
  BinaryImage result;
  result.entry = address_of_json(document.value("entry", JsonDoc(0)));
  result.relocated = document.value("relocated", false);
  result.origin = document.value("origin", "");
  if (!document.at("regions").is_array() || document.at("regions").empty() ||
      document.at("regions").size() > 4096)
    throw FlowError("invalid snapshot region count");
  std::size_t total_bytes = 0;
  for (const auto &row : document.at("regions")) {
    auto encoded = row.at("bytes").get_ref<const std::string &>();
    if (encoded.size() / 2 > maximum_image - total_bytes)
      throw FlowError("snapshot memory limit exceeded");
    total_bytes += encoded.size() / 2;
    ImageRegion region;
    region.begin = address_of_json(row.at("begin"));
    region.bytes = bytes_of_hex(row.at("bytes"));
    region.label = row.value("label", "");
    region.readable = row.value("readable", true);
    region.writable = row.value("writable", false);
    region.executable = row.value("executable", false);
    if (row.contains("source_offset") && !row["source_offset"].is_null())
      region.source_offset = address_of_json(row["source_offset"]);
    result.regions.push_back(std::move(region));
  }
  for (const auto &row : document.value("functions", JsonDoc::array()))
    result.functions.push_back({address_of_json(row.at("begin")),
                                address_of_json(row.at("end")),
                                row.value("label", "")});
  for (const auto &row : document.value("references", JsonDoc::array()))
    result.references.push_back({address_of_json(row.at("source")),
                                 address_of_json(row.at("target")),
                                 row.value("owned", false)});
  result.validate();
  return result;
}
BinaryImage BinaryImage::from_elf(std::span<const std::uint8_t> file) {
  if (file.size() < 64 || little(file, 0, 4) != 0x464c457f || file[4] != 2 ||
      file[5] != 1 || file[6] != 1 || little(file, 18, 2) != 183)
    throw FlowError("expected a little-endian AArch64 ELF64 image");
  auto type = little(file, 16, 2);
  if (type != 2 && type != 3)
    throw FlowError("ELF must be executable or shared object");
  BinaryImage result;
  result.entry = little(file, 24, 8);
  result.relocated = type == 2;
  auto program_offset = little(file, 32, 8), program_size = little(file, 54, 2),
       program_count = little(file, 56, 2);
  if (program_count == 0 || program_count > 4096 || program_size < 56)
    throw FlowError("invalid ELF program table");
  range(file, program_offset, program_size * program_count);
  std::uint64_t mapped_bytes = 0;
  for (std::uint64_t index = 0; index < program_count; ++index) {
    auto record =
        range(file, program_offset + index * program_size, program_size);
    if (little(record, 0, 4) != 1)
      continue;
    auto offset = little(record, 8, 8), address = little(record, 16, 8),
         filesize = little(record, 32, 8), memsize = little(record, 40, 8);
    if (memsize == 0)
      continue;
    if (memsize > maximum_image - mapped_bytes || filesize > memsize)
      throw FlowError("invalid ELF load sizes");
    mapped_bytes += memsize;
    auto bytes = range(file, offset, filesize);
    ImageRegion region;
    region.begin = address;
    region.bytes.resize(static_cast<std::size_t>(memsize));
    std::copy(bytes.begin(), bytes.end(), region.bytes.begin());
    auto flags = little(record, 4, 4);
    region.readable = flags & 4;
    region.writable = flags & 2;
    region.executable = flags & 1;
    region.label = "load_" + std::to_string(index);
    region.source_offset = offset;
    result.regions.push_back(std::move(region));
  }
  auto sections = little(file, 40, 8), stride = little(file, 58, 2),
       count = little(file, 60, 2);
  if (count) {
    if (stride < 64)
      throw FlowError("invalid ELF section stride");
    range(file, sections, stride * count);
    for (std::uint64_t index = 0; index < count; ++index) {
      auto record = range(file, sections + index * stride, stride);
      auto kind = little(record, 4, 4);
      if (kind != 2 && kind != 11)
        continue;
      auto link = little(record, 40, 4), entsize = little(record, 56, 8),
           length = little(record, 32, 8);
      if (link >= count || entsize < 24 || length % entsize ||
          length / entsize > 1000000)
        throw FlowError("invalid ELF symbol table");
      auto strings_header = range(file, sections + link * stride, stride);
      auto strings = range(file, little(strings_header, 24, 8),
                           little(strings_header, 32, 8));
      auto symbols = range(file, little(record, 24, 8), length);
      for (std::uint64_t offset = 0; offset < length; offset += entsize) {
        auto symbol = range(symbols, offset, entsize);
        if ((symbol[4] & 15) != 2 || little(symbol, 6, 2) == 0)
          continue;
        auto begin = little(symbol, 8, 8), size = little(symbol, 16, 8);
        if (size == 0)
          continue;
        if (size > maximum_image ||
            begin > std::numeric_limits<Address>::max() - size)
          throw FlowError("invalid ELF function size");
        auto name = terminated(strings, little(symbol, 0, 4));
        bool duplicate = std::any_of(
            result.functions.begin(), result.functions.end(),
            [&](const auto &function) {
              return function.begin == begin && function.end == begin + size;
            });
        if (!duplicate)
          result.functions.push_back({begin, begin + size, name});
      }
    }
  }
  result.validate();
  return result;
}
BinaryImage BinaryImage::from_flat(std::span<const std::uint8_t> file,
                               const JsonDoc &mapping) {
  BinaryImage result;
  const auto &regions = mapping.at("regions");
  if (!regions.is_array() || regions.empty() || regions.size() > 4096)
    throw FlowError("flat mapping requires 1..4096 regions");
  std::size_t total = 0;
  for (const auto &row : regions) {
    const auto offset = address_of_json(row.at("offset"));
    const auto size = address_of_json(row.at("size"));
    const auto stored = address_of_json(row.value("file_size", JsonDoc(size)));
    if (!size || size > maximum_image - total || stored > size ||
        offset > file.size() || stored > file.size() - offset)
      throw FlowError("flat region exceeds its file or memory bounds");
    total += static_cast<std::size_t>(size);
    ImageRegion region;
    region.begin = address_of_json(row.at("begin"));
    region.bytes.resize(static_cast<std::size_t>(size), 0);
    std::copy_n(file.begin() + static_cast<std::ptrdiff_t>(offset),
                static_cast<std::size_t>(stored), region.bytes.begin());
    region.label = row.at("label").get<std::string>();
    region.readable = row.value("readable", true);
    region.writable = row.value("writable", false);
    region.executable = row.value("executable", false);
    region.source_offset = offset;
    result.regions.push_back(std::move(region));
  }
  const auto functions = mapping.value("functions", JsonDoc::array());
  if (!functions.is_array() || functions.size() > 1000000)
    throw FlowError("invalid flat-image function metadata");
  for (const auto &row : functions)
    result.functions.push_back({address_of_json(row.at("begin")),
                                address_of_json(row.at("end")),
                                row.value("label", std::string{})});
  result.entry = address_of_json(mapping.value("entry", JsonDoc(0)));
  result.relocated = mapping.value("relocated", false);
  result.validate();
  return result;
}
BinaryImage BinaryImage::load(const std::filesystem::path &path) {
  auto data = load_file(path);
  BinaryImage result;
  if (data.size() >= 4 && little(data, 0, 4) == 0x464c457f)
    result = from_elf(data);
  else
    result = from_snapshot(load_document(path));
  result.origin = path.string();
  return result;
}
} // namespace armflow
