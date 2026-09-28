#include <armflow/opcode.hpp>
#include <bit>
#include <capstone/capstone.h>
#include <limits>
namespace armflow {
namespace {
std::int64_t extended(std::uint64_t value, unsigned width) {
  auto sign = std::uint64_t{1} << (width - 1);
  return static_cast<std::int64_t>(value & (sign - 1)) -
         static_cast<std::int64_t>(value & sign);
}
std::optional<Address> displaced(Address base, std::int64_t offset) {
  if (offset >= 0) {
    auto distance = static_cast<Address>(offset);
    if (distance > std::numeric_limits<Address>::max() - base)
      return {};
    return base + distance;
  }
  auto distance = static_cast<Address>(-(offset + 1)) + 1;
  if (distance > base)
    return {};
  return base - distance;
}
int normalized(unsigned reg) {
  if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30)
    return static_cast<int>(reg - ARM64_REG_W0);
  if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28)
    return static_cast<int>(reg - ARM64_REG_X0);
  if (reg == ARM64_REG_X29)
    return 29;
  if (reg == ARM64_REG_X30)
    return 30;
  if (reg == ARM64_REG_SP || reg == ARM64_REG_WSP)
    return 31;
  return -1;
}
std::optional<std::uint32_t> displacement_bits(Address from, Address to,
                                               unsigned bits) {
  if (from % 4 || to % 4)
    return {};
  auto limit = std::uint64_t{1} << (bits + 1);
  if (to >= from) {
    if (to - from >= limit)
      return {};
  } else if (from - to > limit)
    return {};
  return static_cast<std::uint32_t>(((to - from) >> 2) &
                                    ((std::uint64_t{1} << bits) - 1));
}
} // namespace
std::string mnemonic_name(Mnemonic operation) {
  static constexpr const char *names[] = {"unknown",
                                          "nop",
                                          "branch",
                                          "call",
                                          "conditional_branch",
                                          "compare_branch",
                                          "bit_branch",
                                          "indirect_branch",
                                          "indirect_call",
                                          "return",
                                          "load",
                                          "store",
                                          "move_zero",
                                          "move_not",
                                          "move_keep",
                                          "move_register",
                                          "select",
                                          "select_increment",
                                          "select_invert",
                                          "select_negate",
                                          "add",
                                          "subtract",
                                          "and",
                                          "or",
                                          "xor",
                                          "address",
                                          "page_address",
                                          "bitfield",
                                          "compare"};
  return names[static_cast<unsigned>(operation)];
}
bool DecodedWord::writes(unsigned reg) const {
  return reg < 32 && written[reg];
}
OpcodeDecoder::OpcodeDecoder() {
  csh instance = 0;
  if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &instance) != CS_ERR_OK)
    throw FlowError("Capstone initialization failed");
  handle_ = instance;
  if (cs_option(instance, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
    cs_close(&instance);
    throw FlowError("Capstone detail mode unavailable");
  }
}
OpcodeDecoder::~OpcodeDecoder() {
  csh instance = handle_;
  cs_close(&instance);
}
DecodedWord OpcodeDecoder::decode(Address address,
                                           std::uint32_t word) const {
  DecodedWord result;
  result.address = address;
  result.encoding = word;
  result.width = (word >> 31) ? 64 : 32;
  auto bytes = word_bytes(word);
  cs_insn *decoded = nullptr;
  auto count = cs_disasm(handle_, bytes.data(), 4, address, 1, &decoded);
  if (count != 1) {
    result.written.set();
    result.observable = true;
    return result;
  }
  result.valid = true;
  result.text = std::string(decoded->mnemonic) +
                (decoded->op_str[0] ? " " : "") + decoded->op_str;
  cs_regs reads{}, writes{};
  std::uint8_t nread = 0, nwrite = 0;
  if (cs_regs_access(handle_, decoded, reads, &nread, writes, &nwrite) !=
      CS_ERR_OK) {
    result.written.set();
    result.observable = true;
  } else {
    for (unsigned index = 0; index < nread; ++index) {
      if (reads[index] == ARM64_REG_NZCV)
        result.flags_read = true;
      auto reg = normalized(reads[index]);
      if (reg >= 0)
        result.read.set(static_cast<std::size_t>(reg));
    }
    for (unsigned index = 0; index < nwrite; ++index) {
      auto reg = normalized(writes[index]);
      if (reg >= 0)
        result.written.set(static_cast<std::size_t>(reg));
      if (writes[index] == ARM64_REG_NZCV)
        result.flags_written = true;
    }
  }
  result.flags_written =
      result.flags_written || decoded->detail->arm64.update_flags;
  for (unsigned index = 0; index < decoded->detail->groups_count; ++index) {
    auto group = decoded->detail->groups[index];
    if (group == CS_GRP_JUMP || group == CS_GRP_CALL || group == CS_GRP_RET ||
        group == CS_GRP_INT || group == CS_GRP_IRET)
      result.control_transfer = true;
    if (group == CS_GRP_CALL)
      result.call = true;
  }
  // Unmodelled instructions remain observable: only a positive classification
  // relaxes it.
  result.observable = true;
  cs_free(decoded, count);
  const auto dst = static_cast<int>(word & 31),
             left = static_cast<int>((word >> 5) & 31),
             right = static_cast<int>((word >> 16) & 31);
  auto set = [&](Mnemonic operation) {
    result.operation = operation;
    result.destination = dst;
    result.left = left;
    result.right = right;
  };
  if (word == 0xd503201f) {
    result.operation = Mnemonic::nop;
    result.observable = false;
  } else if ((word & 0x7c000000) == 0x14000000) {
    result.call = word >> 31;
    result.operation = result.call ? Mnemonic::call : Mnemonic::branch;
    result.target = displaced(address, extended(word & 0x3ffffff, 26) * 4);
    result.control_transfer = true;
  } else if ((word & 0xff000010) == 0x54000000) {
    result.operation = Mnemonic::conditional_branch;
    result.condition = word & 15;
    result.target = displaced(address, extended((word >> 5) & 0x7ffff, 19) * 4);
    result.control_transfer = true;
  } else if ((word & 0x7e000000) == 0x34000000) {
    result.operation = Mnemonic::compare_branch;
    result.left = dst;
    result.condition = (word >> 24) & 1;
    result.target = displaced(address, extended((word >> 5) & 0x7ffff, 19) * 4);
    result.control_transfer = true;
  } else if ((word & 0x7e000000) == 0x36000000) {
    result.operation = Mnemonic::bit_branch;
    result.left = dst;
    result.condition = (word >> 24) & 1;
    result.bit_index = ((word >> 26) & 32) | ((word >> 19) & 31);
    result.target = displaced(address, extended((word >> 5) & 0x3fff, 14) * 4);
    result.control_transfer = true;
  } else if ((word & 0xfffffc1f) == 0xd61f0000 ||
             (word & 0xfffffc1f) == 0xd63f0000 ||
             (word & 0xfffffc1f) == 0xd65f0000) {
    result.left = left;
    result.operation =
        (word & 0x600000) == 0x200000
            ? Mnemonic::indirect_call
            : ((word & 0x600000) == 0x400000 ? Mnemonic::return_
                                             : Mnemonic::indirect_branch);
    result.call = result.operation == Mnemonic::indirect_call;
    result.control_transfer = true;
  } else if ((word & 0x1f800000) == 0x12800000) {
    auto kind = (word >> 29) & 3;
    auto shift = ((word >> 21) & 3) * 16;
    if ((result.width == 32 && shift >= 32) || kind == 1) {
      result.valid = false;
      result.written.set();
      return result;
    }
    set(kind == 0   ? Mnemonic::move_not
        : kind == 2 ? Mnemonic::move_zero
                    : Mnemonic::move_keep);
    result.shift = shift;
    result.immediate = std::uint64_t((word >> 5) & 0xffff) << shift;
    result.observable = false;
  } else if ((word & 0x7fe0ffe0) == 0x2a0003e0) {
    set(Mnemonic::move_register);
    result.left = right;
    result.observable = false;
  } else if ((word & 0x1fe00800) == 0x1a800000) {
    auto invert = (word >> 30) & 1, change = (word >> 10) & 1;
    set(invert ? (change ? Mnemonic::select_negate : Mnemonic::select_invert)
               : (change ? Mnemonic::select_increment : Mnemonic::select));
    result.condition = (word >> 12) & 15;
    result.observable = false;
  } else if ((word & 0x1f000000) == 0x11000000) {
    auto subtract = (word >> 30) & 1;
    set(subtract ? Mnemonic::subtract : Mnemonic::add);
    result.immediate = std::uint64_t((word >> 10) & 0xfff)
                       << (((word >> 22) & 1) * 12);
    result.right = -1;
    result.observable = false;
    if (result.flags_written && dst == 31 && subtract)
      result.operation = Mnemonic::compare;
  } else if ((word & 0x1f800000) == 0x12000000) {
    auto kind = (word >> 29) & 3;
    set(kind == 1   ? Mnemonic::bit_or
        : kind == 2 ? Mnemonic::bit_xor
                    : Mnemonic::bit_and);
    result.immediate = bitmask_immediate(result.width, (word >> 22) & 1,
                                    (word >> 16) & 63, (word >> 10) & 63);
    result.right = -1;
    result.observable = false;
    if (!result.immediate) {
      result.valid = false;
      result.written.set();
    }
  } else if ((word & 0x1f200000) == 0x0a000000) {
    auto kind = (word >> 29) & 3;
    set(kind == 1   ? Mnemonic::bit_or
        : kind == 2 ? Mnemonic::bit_xor
                    : Mnemonic::bit_and);
    result.shift = (word >> 10) & 63;
    result.shift_kind = (word >> 22) & 3;
    result.observable = false;
  } else if ((word & 0x1f200000) == 0x0b000000) {
    set((word >> 30) & 1 ? Mnemonic::subtract : Mnemonic::add);
    result.shift = (word >> 10) & 63;
    result.shift_kind = (word >> 22) & 3;
    result.observable = false;
    if (result.flags_written && dst == 31 &&
        result.operation == Mnemonic::subtract)
      result.operation = Mnemonic::compare;
  } else if ((word & 0x1f000000) == 0x10000000) {
    set((word >> 31) ? Mnemonic::page_address : Mnemonic::address);
    auto offset =
        extended(((word >> 5) & 0x7ffff) * 4 + ((word >> 29) & 3), 21);
    result.width = 64;
    result.target = displaced((word >> 31) ? address & ~Address{4095} : address,
                              (word >> 31) ? offset * 4096 : offset);
    result.immediate = result.target;
    result.observable = false;
  } else if (!(word & 0x04000000) && ((word & 0x3b200c00) == 0x38200800 ||
                                      (word & 0x3b000000) == 0x39000000 ||
                                      (word & 0x3b200c00) == 0x38000000)) {
    auto size = (word >> 30) & 3, kind = (word >> 22) & 3;
    MemoryAccess memory;
    memory.base = left;
    memory.width = 1u << size;
    memory.signed_value = (kind >= 2);
    bool load = kind != 0;
    set(load ? Mnemonic::load : Mnemonic::store);
    result.width = kind == 2 ? 64 : size == 3 ? 64 : 32;
    if ((word & 0x3b200c00) == 0x38200800) {
      memory.index = right;
      memory.extension = (word >> 13) & 7;
      memory.scale = ((word >> 12) & 1) ? size : 0;
    } else if ((word & 0x3b000000) == 0x39000000)
      memory.displacement =
          static_cast<std::int64_t>((word >> 10) & 0xfff) * (1 << size);
    else
      memory.displacement = extended((word >> 12) & 0x1ff, 9);
    result.memory = memory;
    result.observable = !load && memory.base != 31 && memory.base != 29;
  } else if ((word & 0x3b000000) == 0x18000000 && !(word & 0x4000000)) {
    auto kind = (word >> 30) & 3;
    if (kind < 3) {
      set(Mnemonic::load);
      MemoryAccess memory;
      memory.width = kind == 1 ? 8 : 4;
      memory.signed_value = kind == 2;
      result.memory = memory;
      result.width = kind == 0 ? 32 : 64;
      result.target =
          displaced(address, extended((word >> 5) & 0x7ffff, 19) * 4);
      result.observable = false;
    }
  } else if ((word & 0x1f800000) == 0x13000000) {
    set(Mnemonic::bitfield);
    result.shift = (word >> 16) & 63;
    result.bit_index = (word >> 10) & 63;
    result.shift_kind = (word >> 29) & 3;
    result.observable = false;
  }
  if (result.call) {
    for (unsigned reg = 0; reg <= 18; ++reg)
      result.written.set(reg);
    result.written.set(30);
    result.flags_written = true;
  }
  return result;
}
std::optional<std::uint64_t> bitmask_immediate(unsigned width, unsigned high_bit,
                                          unsigned rotate, unsigned ones) {
  if ((width != 32 && width != 64) || high_bit > 1 || rotate > 63 ||
      ones > 63 || (width == 32 && high_bit))
    return {};
  unsigned pattern = (high_bit << 6) | ((~ones) & 63);
  if (pattern == 0)
    return {};
  auto length = std::bit_width(pattern) - 1;
  if (length < 1)
    return {};
  unsigned size = 1u << length;
  if (size > width)
    return {};
  unsigned level = size - 1, s = ones & level, r = rotate & level;
  if (s == level)
    return {};
  std::uint64_t mask = (std::uint64_t{1} << (s + 1)) - 1;
  auto element_mask =
      size == 64 ? ~std::uint64_t{0} : (std::uint64_t{1} << size) - 1;
  if (r)
    mask = ((mask >> r) | (mask << (size - r))) & element_mask;
  std::uint64_t result = 0;
  for (unsigned bit = 0; bit < width; bit += size)
    result |= mask << bit;
  return result;
}
std::optional<std::uint32_t> direct_branch(Address from, Address to) {
  auto bits = displacement_bits(from, to, 26);
  return bits ? std::optional<std::uint32_t>(0x14000000 | *bits) : std::nullopt;
}
std::optional<std::uint32_t> conditional_branch(Address from, Address to,
                                                unsigned condition) {
  if (condition >= 14)
    return {};
  auto bits = displacement_bits(from, to, 19);
  return bits ? std::optional<std::uint32_t>(0x54000000 | (*bits << 5) |
                                             condition)
              : std::nullopt;
}
std::optional<std::uint32_t> bit_branch(Address from, Address to, unsigned reg,
                                        unsigned bit, bool nonzero) {
  if (reg > 31 || bit > 63)
    return {};
  auto bits = displacement_bits(from, to, 14);
  return bits
             ? std::optional<std::uint32_t>(
                   0x36000000 | (std::uint32_t(nonzero) << 24) |
                   ((bit & 32) << 26) | ((bit & 31) << 19) | (*bits << 5) | reg)
             : std::nullopt;
}
bool condition_passes(unsigned condition, std::uint32_t nzcv) {
  bool n = nzcv & 0x80000000, z = nzcv & 0x40000000, c = nzcv & 0x20000000,
       v = nzcv & 0x10000000;
  bool value = false;
  switch (condition >> 1) {
  case 0:
    value = z;
    break;
  case 1:
    value = c;
    break;
  case 2:
    value = n;
    break;
  case 3:
    value = v;
    break;
  case 4:
    value = c && !z;
    break;
  case 5:
    value = n == v;
    break;
  case 6:
    value = !z && n == v;
    break;
  case 7:
    return true;
  default:
    throw FlowError("invalid condition");
  }
  return condition & 1 ? !value : value;
}
ByteBuffer word_bytes(std::uint32_t word) {
  return {static_cast<std::uint8_t>(word), static_cast<std::uint8_t>(word >> 8),
          static_cast<std::uint8_t>(word >> 16),
          static_cast<std::uint8_t>(word >> 24)};
}
} // namespace armflow
