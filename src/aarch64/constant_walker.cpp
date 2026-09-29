#include <algorithm>
#include <armflow/opcode.hpp>
#include <limits>
namespace armflow {
namespace {
std::uint64_t width_mask(unsigned width) {
  return width == 64 ? ~std::uint64_t{0} : 0xffffffff;
}
void merge_producers(ConstantFact &value, const ConstantFact &other) {
  value.producers.insert(value.producers.end(), other.producers.begin(),
                         other.producers.end());
  std::sort(value.producers.begin(), value.producers.end());
  value.producers.erase(
      std::unique(value.producers.begin(), value.producers.end()),
      value.producers.end());
}
} // namespace
ConstantWalker::ConstantWalker(const BinaryImage &image,
                               const OpcodeDecoder &decoder, unsigned window,
                               unsigned depth)
    : image_(image), decoder_(decoder), window_(window), depth_(depth) {
  if (window == 0 || window > 4096 || depth == 0 || depth > 64)
    throw FlowError("invalid constant-analysis budget");
}
std::optional<Address> ConstantWalker::producer(Address use,
                                                unsigned reg) const {
  if (reg > 30 || use % 4)
    return {};
  const auto *region = image_.region_at(use);
  if (!region && use >= 4)
    region = image_.region_at(use - 4);
  if (!region)
    return {};
  Address lower = region->begin;
  const auto *function = image_.function_at(use);
  if (function)
    lower = std::max(lower, function->begin);
  for (const auto &edge : image_.references)
    if (edge.target >= lower && edge.target <= use &&
        edge.source + 4 != edge.target)
      lower = edge.target;
  Address cursor = use;
  for (unsigned distance = 0; distance < window_ && cursor >= 4; ++distance) {
    cursor -= 4;
    if (cursor < lower)
      break;
    auto word = image_.instruction(cursor);
    if (!word)
      return {};
    auto instruction = decoder_.decode(cursor, *word);
    if (!instruction.valid)
      return {};
    if (instruction.control_transfer) {
      if (instruction.call && !instruction.writes(reg))
        continue;
      return {};
    }
    if (instruction.writes(reg))
      return cursor;
    if (std::any_of(image_.references.begin(), image_.references.end(),
                    [&](const auto &edge) {
                      return edge.target == cursor && edge.source != cursor - 4;
                    }))
      return {};
  }
  return {};
}
std::optional<ConstantFact> ConstantWalker::resolve(Address use, unsigned reg,
                                                    unsigned width) const {
  if (reg > 31 || (width != 32 && width != 64))
    return {};
  unsigned budget = 4096;
  return derive(use, reg, width, depth_, budget);
}
std::optional<ConstantFact> ConstantWalker::derive(Address use, unsigned reg,
                                                   unsigned width,
                                                   unsigned depth,
                                                   unsigned &budget) const {
  if (budget == 0 || depth == 0)
    return {};
  --budget;
  if (reg == 31)
    return ConstantFact{{0}, {}, {}, {}};
  auto location = producer(use, reg);
  if (!location)
    return {};
  auto word = image_.instruction(*location);
  if (!word)
    return {};
  auto instruction = decoder_.decode(*location, *word);
  if (instruction.destination != static_cast<int>(reg))
    return {};
  auto mask = width_mask(instruction.width);
  ConstantFact output;
  output.producers.push_back(*location);
  auto previous = [&](int source) -> std::optional<ConstantFact> {
    if (source < 0 || source > 31)
      return {};
    return derive(*location, static_cast<unsigned>(source), instruction.width,
                  depth - 1, budget);
  };
  auto constant = [&](std::uint64_t number) {
    return ConstantFact{{number & mask}, {}, {}, {}};
  };
  std::optional<ConstantFact> left, right;
  switch (instruction.operation) {
  case Mnemonic::move_zero:
    output.values = {*instruction.immediate & mask};
    break;
  case Mnemonic::move_not:
    output.values = {(~*instruction.immediate) & mask};
    break;
  case Mnemonic::address:
  case Mnemonic::page_address:
    if (!instruction.target)
      return {};
    output.values = {*instruction.target};
    break;
  case Mnemonic::move_keep: {
    left = previous(static_cast<int>(reg));
    if (!left)
      return {};
    output = *left;
    auto field = std::uint64_t{0xffff} << instruction.shift;
    for (auto &value : output.values)
      value = ((value & ~field) | *instruction.immediate) & mask;
    output.producers.push_back(*location);
    break;
  }
  case Mnemonic::move_register: {
    left = previous(instruction.left);
    if (!left)
      return {};
    output = *left;
    output.producers.push_back(*location);
    break;
  }
  case Mnemonic::select:
  case Mnemonic::select_increment:
  case Mnemonic::select_invert:
  case Mnemonic::select_negate: {
    left = previous(instruction.left);
    right = previous(instruction.right);
    if (!left || !right || !left->singleton() || !right->singleton() ||
        instruction.condition >= 14)
      return {};
    auto first = left->values[0], second = right->values[0];
    if (instruction.operation == Mnemonic::select_increment)
      ++second;
    else if (instruction.operation == Mnemonic::select_invert)
      second = ~second;
    else if (instruction.operation == Mnemonic::select_negate)
      second = 0 - second;
    output.values = {first & mask, second & mask};
    output.condition = instruction.condition;
    output.selection = *location;
    merge_producers(output, *left);
    merge_producers(output, *right);
    break;
  }
  case Mnemonic::add:
  case Mnemonic::subtract:
  case Mnemonic::bit_and:
  case Mnemonic::bit_or:
  case Mnemonic::bit_xor: {
    // Register 31 denotes SP, not ZR, in add/sub immediate encodings.
    if ((instruction.operation == Mnemonic::add ||
         instruction.operation == Mnemonic::subtract) &&
        instruction.immediate && instruction.left == 31)
      return {};
    left = previous(instruction.left);
    right = instruction.immediate
                ? std::optional<ConstantFact>(constant(*instruction.immediate))
                : previous(instruction.right);
    if (!left || !right)
      return {};
    if (left->condition && right->condition &&
        (left->condition != right->condition ||
         left->selection != right->selection))
      return {};
    auto count = std::max(left->values.size(), right->values.size());
    if (count == 0 || count > 2)
      return {};
    output.condition = left->condition ? left->condition : right->condition;
    output.selection = left->selection ? left->selection : right->selection;
    for (std::size_t index = 0; index < count; ++index) {
      auto a = left->values[left->singleton() ? 0 : index],
           b = right->values[right->singleton() ? 0 : index];
      if (!instruction.immediate && instruction.shift) {
        if (instruction.shift >= instruction.width)
          return {};
        if (instruction.shift_kind == 0)
          b = (b << instruction.shift) & mask;
        else if (instruction.shift_kind == 1)
          b >>= instruction.shift;
        else
          return {};
      }
      if (instruction.operation == Mnemonic::add)
        output.values.push_back((a + b) & mask);
      else if (instruction.operation == Mnemonic::subtract)
        output.values.push_back((a - b) & mask);
      else if (instruction.operation == Mnemonic::bit_and)
        output.values.push_back((a & b) & mask);
      else if (instruction.operation == Mnemonic::bit_or)
        output.values.push_back((a | b) & mask);
      else
        output.values.push_back((a ^ b) & mask);
    }
    merge_producers(output, *left);
    merge_producers(output, *right);
    break;
  }
  case Mnemonic::bitfield: {
    left = previous(instruction.left);
    if (!left)
      return {};
    auto rotate = instruction.shift, ones = instruction.bit_index,
         bits = instruction.width;
    if (rotate >= bits || ones >= bits)
      return {};
    output = *left;
    for (auto &value : output.values) {
      if (instruction.shift_kind == 2) {
        if (ones >= rotate) {
          auto size = ones - rotate + 1;
          auto keep =
              size == 64 ? ~std::uint64_t{0} : (std::uint64_t{1} << size) - 1;
          value = (value >> rotate) & keep;
        } else {
          auto keep = (std::uint64_t{1} << (ones + 1)) - 1;
          value = ((value & keep) << (bits - rotate)) & mask;
        }
      } else if (instruction.shift_kind == 0 && ones >= rotate) {
        auto size = ones - rotate + 1;
        auto keep =
            size == 64 ? ~std::uint64_t{0} : (std::uint64_t{1} << size) - 1;
        value = (value >> rotate) & keep;
        if (size < 64 && (value & (std::uint64_t{1} << (size - 1))))
          value |= ~keep;
        value &= mask;
      } else
        return {};
    }
    output.producers.push_back(*location);
    break;
  }
  default:
    return {};
  }
  for (auto &value : output.values)
    value &= width_mask(width) & mask;
  if (output.values.size() == 2 && output.values[0] == output.values[1]) {
    output.values.resize(1);
    output.condition.reset();
    output.selection.reset();
  }
  return output;
}
} // namespace armflow
