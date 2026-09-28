#pragma once
#include <armflow/binary_image.hpp>
#include <array>
#include <bitset>
#include <functional>
#include <memory>
namespace armflow {
enum class Mnemonic {
  unknown,
  nop,
  branch,
  call,
  conditional_branch,
  compare_branch,
  bit_branch,
  indirect_branch,
  indirect_call,
  return_,
  load,
  store,
  move_zero,
  move_not,
  move_keep,
  move_register,
  select,
  select_increment,
  select_invert,
  select_negate,
  add,
  subtract,
  bit_and,
  bit_or,
  bit_xor,
  address,
  page_address,
  bitfield,
  compare
};
std::string mnemonic_name(Mnemonic operation);
struct MemoryAccess {
  int base = -1, index = -1;
  std::int64_t displacement = 0;
  unsigned width = 0, scale = 0, extension = 0;
  bool signed_value = false, writeback = false;
};
struct DecodedWord {
  Address address = 0;
  std::uint32_t encoding = 0;
  Mnemonic operation = Mnemonic::unknown;
  unsigned width = 64;
  int destination = -1, left = -1, right = -1;
  std::optional<std::uint64_t> immediate;
  std::optional<Address> target;
  std::optional<MemoryAccess> memory;
  unsigned condition = 14, shift = 0, shift_kind = 0, bit_index = 0;
  bool valid = false, flags_written = false, flags_read = false,
       control_transfer = false, call = false, observable = false;
  std::bitset<32> written, read;
  std::string text;
  bool writes(unsigned reg) const;
};
class OpcodeDecoder {
public:
  OpcodeDecoder();
  ~OpcodeDecoder();
  OpcodeDecoder(const OpcodeDecoder &) = delete;
  OpcodeDecoder &operator=(const OpcodeDecoder &) = delete;
  DecodedWord decode(Address address, std::uint32_t word) const;

private:
  std::size_t handle_ = 0;
};
std::optional<std::uint64_t> bitmask_immediate(unsigned width, unsigned high_bit,
                                          unsigned rotate, unsigned ones);
std::optional<std::uint32_t> direct_branch(Address from, Address to);
std::optional<std::uint32_t> conditional_branch(Address from, Address to,
                                                unsigned condition);
std::optional<std::uint32_t> bit_branch(Address from, Address to, unsigned reg,
                                        unsigned bit, bool nonzero);
bool condition_passes(unsigned condition, std::uint32_t nzcv);
ByteBuffer word_bytes(std::uint32_t word);
struct ConstantFact {
  std::vector<std::uint64_t> values;
  std::optional<unsigned> condition;
  std::optional<Address> selection;
  std::vector<Address> producers;
  bool singleton() const { return values.size() == 1; }
};
class ConstantWalker {
public:
  ConstantWalker(const BinaryImage &image, const OpcodeDecoder &decoder,
                  unsigned window = 128, unsigned depth = 16);
  std::optional<ConstantFact> resolve(Address use, unsigned reg,
                                       unsigned width = 32) const;
  std::optional<Address> producer(Address use, unsigned reg) const;

private:
  const BinaryImage &image_;
  const OpcodeDecoder &decoder_;
  unsigned window_, depth_;
  std::optional<ConstantFact> derive(Address use, unsigned reg, unsigned width,
                                      unsigned depth, unsigned &budget) const;
};
} // namespace armflow
