#include <armflow/flow_analysis.hpp>
#include <algorithm>
#include <bit>
namespace armflow {
namespace {
std::optional<Address> nearest_store(const BinaryImage &image,
                                     const OpcodeDecoder &decoder,
                                     Address from, Address lower,
                                     const MemoryAccess &slot,
                                     unsigned budget) {
  Address current = from;
  for (unsigned count = 0; count < budget && current >= 4; ++count) {
    current -= 4;
    if (current < lower)
      return {};
    auto word = image.instruction(current);
    if (!word)
      return {};
    auto instruction = decoder.decode(current, *word);
    if (!instruction.valid || instruction.control_transfer)
      return {};
    if (instruction.operation == Mnemonic::unknown && instruction.observable)
      return {};
    if (instruction.operation == Mnemonic::store && instruction.memory &&
        instruction.memory->base == slot.base &&
        instruction.memory->displacement == slot.displacement &&
        instruction.memory->index < 0 && instruction.memory->width == 4)
      return current;
    // Any other store may alias the slot; accepting it would need a memory
    // proof.
    if (instruction.operation == Mnemonic::store)
      return {};
    if (instruction.writes(static_cast<unsigned>(slot.base)))
      return {};
    for (const auto &edge : image.references)
      if (edge.target == current && edge.source + 4 != current)
        return {};
  }
  return {};
}
std::optional<JsonDoc> transform_chain(const BinaryImage &image,
                                    const OpcodeDecoder &decoder,
                                    const ConstantWalker &tracker, Address use,
                                    unsigned reg, const MemoryAccess &slot) {
  JsonDoc chain = JsonDoc::array();
  for (unsigned depth = 0; depth < 16; ++depth) {
    auto producer = tracker.producer(use, reg);
    if (!producer)
      return {};
    auto instruction = decoder.decode(*producer, *image.instruction(*producer));
    if (instruction.operation == Mnemonic::load && instruction.memory &&
        instruction.memory->base == slot.base &&
        instruction.memory->displacement == slot.displacement &&
        instruction.memory->index < 0 && instruction.memory->width == 4) {
      if (chain.empty())
        return {};
      return JsonDoc{{"source", format_address(*producer)},
                  {"operations_reverse", chain}};
    }
    if ((instruction.operation != Mnemonic::add &&
         instruction.operation != Mnemonic::subtract &&
         instruction.operation != Mnemonic::bit_xor &&
         instruction.operation != Mnemonic::bit_and &&
         instruction.operation != Mnemonic::bit_or) ||
        !instruction.immediate || instruction.left < 0)
      return {};
    chain.push_back({{"at", format_address(*producer)},
                     {"operation", mnemonic_name(instruction.operation)},
                     {"immediate", format_address(*instruction.immediate)}});
    reg = static_cast<unsigned>(instruction.left);
    use = *producer;
  }
  return {};
}
std::optional<BranchTransition> flag_byte(const BinaryImage &image,
                                        const OpcodeDecoder &decoder,
                                        const ConstantWalker &tracker,
                                        const SwitchSite &site) {
  auto and_pc =
      tracker.producer(site.load_target, static_cast<unsigned>(site.state_reg));
  if (!and_pc)
    return {};
  auto mask = decoder.decode(*and_pc, *image.instruction(*and_pc));
  if (mask.operation != Mnemonic::bit_and || !mask.immediate ||
      *mask.immediate == 0 || (*mask.immediate & (*mask.immediate - 1)) ||
      mask.left < 0)
    return {};
  auto extract_pc = tracker.producer(*and_pc, static_cast<unsigned>(mask.left));
  if (!extract_pc)
    return {};
  auto extract = decoder.decode(*extract_pc, *image.instruction(*extract_pc));
  if (extract.operation != Mnemonic::bitfield || extract.shift_kind != 0 ||
      extract.shift != 0 || extract.bit_index != 0 || extract.left < 0)
    return {};
  auto byte_pc =
      tracker.producer(*extract_pc, static_cast<unsigned>(extract.left));
  if (!byte_pc)
    return {};
  auto word = *image.instruction(*byte_pc);
  // LDARB Wt,[Xn] including the acquire ordering operation, which stays intact.
  if ((word & 0xfffffc00) != 0x08dffc00)
    return {};
  BranchTransition value;
  value.branch = site.branch;
  value.arrival = site.head;
  value.category = "choice";
  value.state = ConstantFact{
      {0, *mask.immediate}, {}, {}, {*and_pc, *extract_pc, *byte_pc}};
  value.predicate = {{"kind", "bit"},
                     {"register", site.state_reg},
                     {"bit", std::countr_zero(*mask.immediate)},
                     {"selection", format_address(*and_pc)}};
  return value;
}
} // namespace
std::vector<BranchTransition>
classify_transitions(const BinaryImage &image, const OpcodeDecoder &decoder,
                     const FlowSettings &settings,
                     const std::vector<SwitchSite> &sites) {
  std::vector<BranchTransition> result;
  ConstantWalker tracker(image, decoder, settings.lookback);
  for (const auto &site : sites) {
    if (site.model == "single_level") {
      BranchTransition transition;
      transition.branch = site.branch;
      transition.arrival = site.head;
      auto width = site.target_access && (site.target_access->extension == 2 ||
                                          site.target_access->extension == 6)
                       ? 32u
                       : 64u;
      transition.state = tracker.resolve(
          site.load_target, static_cast<unsigned>(site.state_reg), width);
      if (!transition.state) {
        auto byte = flag_byte(image, decoder, tracker, site);
        if (byte) {
          result.push_back(*byte);
          continue;
        }
      }
      if (transition.state) {
        transition.category =
            transition.state->singleton() ? "constant" : "choice";
        if (transition.state->condition)
          transition.predicate = {
              {"kind", "condition"},
              {"condition", *transition.state->condition},
              {"selection", format_address(*transition.state->selection)}};
      } else
        transition.reason = "index is not a bounded constant or binary choice";
      result.push_back(std::move(transition));
      continue;
    }
    for (auto arrival : site.arrivals) {
      BranchTransition transition;
      transition.branch = site.branch;
      transition.arrival = arrival;
      if (!site.state_slot) {
        transition.reason = "state slot is unresolved";
        result.push_back(transition);
        continue;
      }
      transition.state_store =
          nearest_store(image, decoder, arrival, site.parent, *site.state_slot,
                        settings.lookback);
      if (!transition.state_store) {
        transition.reason = "no unambiguous preceding state store";
        result.push_back(transition);
        continue;
      }
      auto store = decoder.decode(*transition.state_store,
                                  *image.instruction(*transition.state_store));
      transition.state =
          tracker.resolve(*transition.state_store,
                          static_cast<unsigned>(store.destination), 32);
      if (transition.state) {
        transition.category =
            transition.state->singleton() ? "constant" : "choice";
        if (transition.state->condition)
          transition.predicate = {
              {"kind", "condition"},
              {"condition", *transition.state->condition},
              {"selection", format_address(*transition.state->selection)}};
      } else {
        auto transform = transform_chain(
            image, decoder, tracker, *transition.state_store,
            static_cast<unsigned>(store.destination), *site.state_slot);
        if (transform) {
          transition.category = "transform";
          transition.transform = *transform;
        } else
          transition.reason =
              "stored value cannot be established within analysis bounds";
      }
      result.push_back(std::move(transition));
    }
  }
  return result;
}
} // namespace armflow
