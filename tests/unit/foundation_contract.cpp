#include "../support/checks.hpp"
#include <armflow/opcode.hpp>
#include <iostream>
using namespace armflow;
using namespace armflow_tests;
namespace {
BinaryImage code(std::initializer_list<std::uint32_t> words) {
  BinaryImage image;
  ImageRegion region;
  region.begin = 0x100000;
  region.executable = true;
  region.label = "test";
  for (auto word : words) {
    auto bytes = word_bytes(word);
    region.bytes.insert(region.bytes.end(), bytes.begin(), bytes.end());
  }
  image.regions.push_back(region);
  image.functions.push_back({region.begin, region.end(), "fixture"});
  image.relocated = true;
  return image;
}
} // namespace
int main() {
  OpcodeDecoder decoder;
  check(sha256_hex({}) ==
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "SHA256 empty known answer");
  const ByteBuffer abc{'a', 'b', 'c'};
  check(sha256_hex(abc) ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "SHA256 abc known answer");
  auto image =
      code({0x52824680, 0x72b579a0, 0x11001c01, 0x2a0103e2, 0xd503201f});
  image.validate();
  check(image.integer(0x100000, 4) == 0x52824680, "little-endian read");
  check(!image.integer(0xffffc, 4), "unmapped read");
  check(!image.instruction(0x100001), "unaligned instruction");
  auto restored = BinaryImage::from_snapshot(image.snapshot());
  check(restored.fingerprint() == image.fingerprint(), "snapshot roundtrip");
  restored.origin = "elsewhere";
  check(restored.fingerprint() == image.fingerprint(),
        "identity excludes origin path");
  restored.replace(0x100000, word_bytes(0xd503201f));
  check(restored.fingerprint() != image.fingerprint(), "identity binds bytes");
  rejects(
      [&] {
        auto broken = image;
        broken.regions.push_back(broken.regions.front());
        broken.validate();
      },
      "overlap rejected");
  rejects(
      [&] {
        auto broken = image;
        broken.regions[0].begin = ~Address{0};
        broken.validate();
      },
      "address wrap rejected");
  rejects([&] { address_of_json(JsonDoc(-1)); }, "negative address rejected");
  rejects([&] { address_of_json(JsonDoc("0x")); },
          "empty hex address rejected");
  rejects([&] { bytes_of_hex("zz"); }, "invalid hex rejected");
  ConstantWalker tracker(image, decoder);
  auto value = tracker.resolve(0x100010, 2);
  check(value && value->singleton() && value->values[0] == 0xabcd123b,
        "MOVZ MOVK ADD register-copy chain");
  auto unknown = code({0x528002a0, 0x1b027c20, 0xd503201f});
  check(!ConstantWalker(unknown, decoder).resolve(0x100008, 0),
        "unknown multiply clobber cannot expose stale constant");
  auto selected = code({0x52800020, 0x52800041, 0x1a810002, 0xd503201f});
  auto pair = ConstantWalker(selected, decoder).resolve(0x10000c, 2);
  check(pair && pair->values == std::vector<std::uint64_t>{1, 2} &&
            pair->condition == 0,
        "CSEL ordered alternatives");
  auto call = code({0x52800020, 0x94000001, 0xd503201f});
  check(!ConstantWalker(call, decoder).resolve(0x100008, 0),
        "call destroys volatile constant");
  for (int delta : {-134217728, -4096, -4, 0, 4, 4096, 134217724}) {
    Address from = 0x10000000,
            to = static_cast<Address>(static_cast<std::int64_t>(from) + delta);
    auto word = direct_branch(from, to);
    check(word && decoder.decode(from, *word).target == to,
          "B signed roundtrip");
  }
  check(!direct_branch(0, 134217728), "B positive limit");
  check(!direct_branch(0x10000000, 0x10000002), "B alignment");
  for (unsigned condition = 0; condition < 14; ++condition) {
    auto word = conditional_branch(0x100000, 0x100040, condition);
    auto instruction = decoder.decode(0x100000, *word);
    check(instruction.target == 0x100040 && instruction.condition == condition,
          "B.cond roundtrip");
  }
  for (unsigned bit = 0; bit < 64; ++bit) {
    auto word = bit_branch(0x100000, 0x100100, 12, bit, bit % 2);
    auto instruction = decoder.decode(0x100000, *word);
    check(instruction.target == 0x100100 && instruction.bit_index == bit &&
              instruction.left == 12,
          "TBZ/TBNZ roundtrip");
  }
  check(!conditional_branch(0, 0, 14), "unconditional condition not emitted");
  check(bitmask_immediate(32, 0, 0, 7) == 255, "logical immediate byte");
  check(!bitmask_immediate(32, 1, 0, 7), "32-bit N restriction");
  check(!bitmask_immediate(64, 1, 0, 63), "all-ones immediate unallocated");
  check(decoder.decode(0x100000, 0xd61f0100).operation ==
            Mnemonic::indirect_branch,
        "BR classification");
  check(decoder.decode(0x100000, 0xd63f0100).operation ==
            Mnemonic::indirect_call,
        "BLR classification");
  check(decoder.decode(0x100000, 0xd65f03c0).operation == Mnemonic::return_,
        "RET classification");
  for (unsigned flags = 0; flags < 16; ++flags)
    for (unsigned condition = 0; condition < 14; condition += 2)
      check(condition_passes(condition, flags << 28) !=
                condition_passes(condition + 1, flags << 28),
            "opposite conditions");
  auto resolved = [&](std::initializer_list<std::uint32_t> words, unsigned reg,
                      std::uint64_t expected, const std::string &name) {
    auto fixture = code(words);
    auto found =
        ConstantWalker(fixture, decoder).resolve(fixture.regions[0].end(), reg);
    check(found && found->singleton() && found->values[0] == expected, name);
  };
  resolved({0x52b7dde8}, 8, 0xbeef0000, "shifted MOVZ");
  resolved({0x12800028}, 8, 0xfffffffe, "MOVN inversion");
  resolved({0x528001e9, 0x51004128}, 8, 0xffffffff, "modular subtraction");
  resolved({0x52800009, 0x11400928}, 8, 0x2000, "ADD LSL12");
  resolved({0x52801e09, 0x528001ea, 0x2a0a0128}, 8, 255,
           "ORR register constants");
  resolved({0x52801fe9, 0x528001ea, 0x4a0a0128}, 8, 240,
           "EOR register constants");
  resolved({0x52824693, 0x94000001}, 19, 0x1234,
           "callee-saved value survives a call");
  resolved({0x52800008, 0x521c0908}, 8, 0x70, "logical immediate propagation");
  auto lone_keep = code({0x72b579a8});
  check(!ConstantWalker(lone_keep, decoder)
             .resolve(lone_keep.regions[0].end(), 8),
        "MOVK needs prior value");
  auto stack_pointer = code({0x110003e0});
  check(!ConstantWalker(stack_pointer, decoder)
             .resolve(stack_pointer.regions[0].end(), 0),
        "SP is not zero in ADD immediate");
  auto entry_join = code({0x52800020, 0xd503201f});
  entry_join.references.push_back({0x200000, 0x100004, false});
  check(!ConstantWalker(entry_join, decoder).resolve(0x100004, 0),
        "external basic-block entry prevents stale constant");
  auto store = decoder.decode(0x100000, 0xb9001fa8);
  check(store.operation == Mnemonic::store && store.memory &&
            store.memory->base == 29 && store.memory->displacement == 28 &&
            !store.writes(8),
        "state store operands and write set");
  auto negative = decoder.decode(0x100000, 0xb89fc3a8);
  check(negative.memory && negative.memory->displacement == -4 &&
            negative.memory->signed_value && negative.width == 64,
        "signed stack state load");
  auto table = decoder.decode(0x100000, 0xb8a95948);
  check(table.memory && table.memory->base == 10 && table.memory->index == 9 &&
            table.memory->scale == 2 && table.memory->extension == 2,
        "UXTW table index");
  check(decoder.decode(0x1000, 0xd0000000).target == 0x3000,
        "ADRP signed page materialization");
  check(decoder.decode(0x1000, 0x2a0203e8).operation == Mnemonic::move_register,
        "MOV alias decoded explicitly");
  std::cout << passed << " checks passed; " << failed << " failed\n";
  return failed ? 1 : 0;
}
