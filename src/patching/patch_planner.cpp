#include <algorithm>
#include <armflow/patching.hpp>
#include <deque>
#include <set>
namespace armflow {
namespace {
bool dead_before_read(const BinaryImage &image, const OpcodeDecoder &decoder,
                      Address begin, unsigned reg, bool flags = false) {
  std::deque<Address> pending{begin};
  std::set<Address> seen;
  unsigned budget = maximum_walk_instructions;
  while (!pending.empty()) {
    auto address = pending.front();
    pending.pop_front();
    while (budget > 0) {
      --budget;
      if (!seen.insert(address).second)
        break;
      auto word = image.instruction(address);
      if (!word)
        return false;
      auto instruction = decoder.decode(address, *word);
      if (!instruction.valid)
        return false;
      if (flags ? instruction.flags_read : instruction.read[reg])
        return false;
      if (flags ? instruction.flags_written : instruction.writes(reg))
        break;
      if (instruction.operation == Mnemonic::return_) {
        // Return/argument registers and platform/callee-saved registers remain
        // observable across a call. A real restoring write must kill their
        // old value before RET; ABI membership is not evidence of deadness.
        if (!flags && (reg <= 7 || reg >= 18))
          return false;
        break;
      }
      if (instruction.call)
        return false;
      if (instruction.operation == Mnemonic::branch) {
        if (!instruction.target)
          return false;
        address = *instruction.target;
        continue;
      }
      if (instruction.operation == Mnemonic::conditional_branch ||
          instruction.operation == Mnemonic::compare_branch ||
          instruction.operation == Mnemonic::bit_branch) {
        if (!instruction.target)
          return false;
        pending.push_back(*instruction.target);
      } else if (instruction.control_transfer)
        return false;
      address += 4;
    }
    if (!budget)
      return false;
  }
  return true;
}
bool quiet_flags(const BinaryImage &image, const OpcodeDecoder &decoder,
                 Address after, Address before) {
  if (after >= before || before - after > 16384)
    return false;
  for (Address address = after + 4; address < before; address += 4) {
    auto word = image.instruction(address);
    if (!word)
      return false;
    auto instruction = decoder.decode(address, *word);
    if (!instruction.valid || instruction.flags_written ||
        instruction.control_transfer)
      return false;
  }
  return true;
}
bool has_external_entry(const BinaryImage &image, Address start, Address end) {
  for (const auto &edge : image.references)
    if (edge.target > start && edge.target <= end &&
        (edge.source < start || edge.source >= end))
      return true;
  return false;
}
WordEdit edit(const BinaryImage &image, const SwitchSite &site, Address address,
              std::uint32_t word, std::optional<Address> target,
              const std::string &reason) {
  return {address,          site.parent, site.branch, image.read(address, 4),
          word_bytes(word), target,      reason};
}
bool private_stack_slot(const BinaryImage &image, const OpcodeDecoder &decoder,
                        const SwitchSite &site) {
  if (!site.state_slot || site.state_slot->base != 31 ||
      site.state_slot->index != -1 || site.state_slot->width != 4 ||
      site.state_slot->displacement < 0)
    return false;
  const auto first_word = image.instruction(site.parent);
  if (!first_word)
    return false;
  const auto frame = decoder.decode(site.parent, *first_word);
  if (frame.operation != Mnemonic::subtract || frame.destination != 31 ||
      frame.left != 31 || !frame.immediate || *frame.immediate < 16 ||
      *frame.immediate > 65536 || frame.flags_written ||
      static_cast<std::uint64_t>(site.state_slot->displacement) + 4 >
          *frame.immediate)
    return false;
  for (const auto &edge : image.references)
    if (edge.target >= site.parent && edge.target < site.parent_end &&
        (edge.target == site.parent || edge.source < site.parent ||
         edge.source >= site.parent_end))
      return false;
  for (auto address = site.parent; address < site.parent_end; address += 4) {
    const auto word = image.instruction(address);
    if (!word)
      return false;
    const auto instruction = decoder.decode(address, *word);
    if (!instruction.valid || instruction.call)
      return false;
    if (instruction.writes(31)) {
      if (address == site.parent)
        continue;
      if (instruction.operation != Mnemonic::add ||
          instruction.destination != 31 || instruction.left != 31 ||
          instruction.immediate != frame.immediate || instruction.flags_written)
        return false;
      auto next = image.instruction(address + 4);
      if (!next ||
          decoder.decode(address + 4, *next).operation != Mnemonic::return_)
        return false;
    } else if (instruction.read[31] && !instruction.memory) {
      // Deriving a general pointer from SP would let the slot escape. Unknown
      // SP-reading instructions also require a stronger proof than this model.
      return false;
    }
    if (instruction.memory && instruction.memory->base == 31 &&
        (instruction.memory->index != -1 || instruction.memory->writeback))
      return false;
  }
  return true;
}
bool overwritten_stack_slot(const BinaryImage &image,
                            const OpcodeDecoder &decoder,
                            const SwitchSite &site, Address begin) {
  if (!private_stack_slot(image, decoder, site))
    return false;
  const auto &slot = *site.state_slot;
  std::deque<Address> pending{begin};
  std::set<Address> seen;
  unsigned budget = maximum_walk_instructions;
  while (!pending.empty()) {
    auto address = pending.front();
    pending.pop_front();
    while (budget) {
      --budget;
      if (address < site.parent || address >= site.parent_end)
        return false;
      if (!seen.insert(address).second)
        break;
      const auto word = image.instruction(address);
      if (!word)
        return false;
      const auto instruction = decoder.decode(address, *word);
      if (!instruction.valid || instruction.call)
        return false;
      if (instruction.operation == Mnemonic::return_)
        break;
      if (instruction.writes(31)) {
        // private_stack_slot established that every post-prologue SP update is
        // the frame release immediately followed by RET.
        if (instruction.operation != Mnemonic::add)
          return false;
        break;
      }
      if (instruction.memory) {
        const auto &memory = *instruction.memory;
        if (memory.base != slot.base || memory.index != -1 ||
            memory.writeback || memory.width == 0)
          return false;
        const bool overlaps =
            memory.displacement < slot.displacement + 4 &&
            memory.displacement + static_cast<std::int64_t>(memory.width) >
                slot.displacement;
        if (overlaps) {
          if (instruction.operation == Mnemonic::store &&
              memory.displacement <= slot.displacement &&
              memory.displacement + static_cast<std::int64_t>(memory.width) >=
                  slot.displacement + 4)
            break;
          return false;
        }
      }
      if (instruction.operation == Mnemonic::branch) {
        if (!instruction.target)
          return false;
        address = *instruction.target;
        continue;
      }
      if (instruction.operation == Mnemonic::conditional_branch ||
          instruction.operation == Mnemonic::compare_branch ||
          instruction.operation == Mnemonic::bit_branch) {
        if (!instruction.target)
          return false;
        pending.push_back(*instruction.target);
      } else if (instruction.control_transfer)
        return false;
      address += 4;
    }
    if (!budget)
      return false;
  }
  return true;
}
bool table_is_readonly(const BinaryImage &image,
                       const std::optional<Address> &table) {
  if (!table)
    return false;
  auto region = image.region_at(*table);
  return region && region->readable && !region->writable;
}
} // namespace
PatchPlan plan_patches(const BinaryImage &image, const OpcodeDecoder &decoder,
                       const FlowSettings &settings,
                       const std::vector<SwitchSite> &sites,
                       const std::vector<ResolvedBranch> &flows,
                       const SurveyObservations &observed) {
  PatchPlan plan;
  plan.source_sha256 = image.fingerprint();
  std::set<std::pair<Address, Address>> graph;
  for (const auto &flow : flows) {
    const auto &transition = flow.transition;
    const SwitchSite *site = nullptr;
    for (const auto &candidate : sites)
      if (candidate.branch == transition.branch) {
        site = &candidate;
        break;
      }
    if (!site)
      throw FlowError("flow has no matching dispatcher");
    for (const auto &record : flow.targets)
      if (record.destination && record.evidence != "invalid" &&
          record.evidence != "conflict")
        graph.emplace(site->branch, *record.destination);
    auto skip = [&](const std::string &reason) {
      plan.skipped.push_back({{"site", format_address(site->branch)},
                              {"arrival", format_address(transition.arrival)},
                              {"reason", reason}});
    };
    if (transition.category != "constant" && transition.category != "choice") {
      skip("value is unknown or transformed");
      continue;
    }
    if (flow.targets.empty() || flow.targets.size() > 2 ||
        std::any_of(
            flow.targets.begin(), flow.targets.end(), [](const auto &target) {
              return !target.destination || target.evidence == "invalid" ||
                     target.evidence == "conflict";
            })) {
      skip("target evidence is missing, invalid or conflicting");
      continue;
    }
    if (site->model != "comparison_tree" && site->arrivals.size() != 1) {
      skip("shared dispatcher has multiple arrivals");
      continue;
    }
    if (site->detail.value("interior_entry", false) ||
        has_external_entry(image, site->head, site->branch)) {
      skip("dispatcher has an interior control-flow entry");
      continue;
    }
    if (site->model != "comparison_tree" &&
        (!table_is_readonly(image, site->target_table) ||
         (site->model == "two_level" &&
          !table_is_readonly(image, site->index_table)))) {
      skip("table stability is not established in readonly mapped memory");
      continue;
    }
    std::set<Address> destinations;
    for (const auto &target : flow.targets)
      destinations.insert(*target.destination);
    auto observation = observed.targets.find(site->branch);
    if (observation != observed.targets.end() &&
        std::any_of(
            observation->second.begin(), observation->second.end(),
            [&](Address target) { return !destinations.contains(target); })) {
      skip("trace includes an unexplained target");
      continue;
    }
    if (site->model == "comparison_tree") {
      auto back = image.instruction(transition.arrival);
      auto instruction =
          back ? decoder.decode(transition.arrival, *back) : DecodedWord{};
      if (instruction.operation != Mnemonic::branch ||
          instruction.target != site->head || !transition.state_store ||
          *transition.state_store >= transition.arrival ||
          transition.arrival - *transition.state_store > 64 ||
          has_external_entry(image, *transition.state_store,
                             transition.arrival)) {
        skip("comparison-tree back edge lacks an unambiguous stored state and "
             "B head");
        continue;
      }
      bool gap_is_padding = true;
      for (auto cursor = *transition.state_store + 4;
           cursor < transition.arrival; cursor += 4) {
        const auto word = image.instruction(cursor);
        if (!word || decoder.decode(cursor, *word).operation != Mnemonic::nop)
          gap_is_padding = false;
      }
      if (!gap_is_padding) {
        skip("comparison-tree terminator gap contains an effect");
        continue;
      }
      if (site->state_reg < 0) {
        skip("comparison-tree state register is missing");
        continue;
      }
      const auto stored = decoder.decode(
          *transition.state_store, *image.instruction(*transition.state_store));
      bool flags_dead = true, state_reload_dead = true;
      for (auto target : destinations) {
        flags_dead =
            flags_dead && dead_before_read(image, decoder, target, 0, true);
        state_reload_dead =
            state_reload_dead &&
            dead_before_read(image, decoder, target,
                             static_cast<unsigned>(site->state_reg));
      }
      if (!flags_dead) {
        skip("comparison-tree flags remain live at handler entry");
        continue;
      }
      const bool reload_preserved = stored.destination == site->state_reg &&
                                    site->state_slot &&
                                    !site->state_slot->signed_value;
      if (!reload_preserved && !state_reload_dead) {
        skip("comparison-tree state reload remains live");
        continue;
      }
      if (destinations.size() == 1) {
        const auto target = *destinations.begin();
        const auto branch = direct_branch(transition.arrival, target);
        if (!branch) {
          skip("direct branch is outside range");
          continue;
        }
        plan.edits.push_back(
            edit(image, *site, transition.arrival, *branch, target,
                 "comparison-tree constant back edge; state store preserved"));
        continue;
      }
      if (flow.targets.size() != 2 || transition.predicate.is_null() ||
          transition.predicate.value("kind", std::string{}) != "condition") {
        skip("comparison-tree binary edge lacks an established condition");
        continue;
      }
      const auto selection =
          address_of_json(transition.predicate.at("selection"));
      const auto condition =
          transition.predicate.at("condition").get<unsigned>();
      if (!quiet_flags(image, decoder, selection, transition.arrival)) {
        skip("comparison-tree condition changed before the back edge");
        continue;
      }
      const auto first = *flow.targets[0].destination,
                 second = *flow.targets[1].destination;
      if (first == transition.arrival + 4 || second == transition.arrival + 4) {
        const bool inverted = first == transition.arrival + 4;
        const auto target = inverted ? second : first;
        const auto branch = conditional_branch(transition.arrival, target,
                                               condition ^ (inverted ? 1 : 0));
        if (branch) {
          plan.edits.push_back(edit(image, *site, transition.arrival, *branch,
                                    target,
                                    "comparison-tree binary edge with natural "
                                    "fallthrough; state store preserved"));
          continue;
        }
      }
      if (*transition.state_store + 8 <= transition.arrival) {
        const auto branch =
            conditional_branch(transition.arrival - 4, first, condition);
        const auto other = direct_branch(transition.arrival, second);
        if (branch && other) {
          plan.edits.push_back(edit(image, *site, transition.arrival - 4,
                                    *branch, first,
                                    "comparison-tree binary edge uses existing "
                                    "padding; state store preserved"));
          plan.edits.push_back(edit(image, *site, transition.arrival, *other,
                                    second,
                                    "comparison-tree alternate target"));
          continue;
        }
      }
      // Compact legacy terminators have only CSEL; STR; B. Reuse those slots
      // only when both selected registers and the private stack state become
      // dead.
      const auto selected_word = image.instruction(selection);
      const auto selected = selected_word
                                ? decoder.decode(selection, *selected_word)
                                : DecodedWord{};
      bool removable =
          selection + 4 == *transition.state_store &&
          *transition.state_store + 4 == transition.arrival &&
          selected.destination >= 0 &&
          selected.destination == stored.destination && state_reload_dead &&
          (selected.operation == Mnemonic::select ||
           selected.operation == Mnemonic::select_increment ||
           selected.operation == Mnemonic::select_invert ||
           selected.operation == Mnemonic::select_negate) &&
          !has_external_entry(image, selection, transition.arrival);
      for (auto target : destinations)
        removable =
            removable &&
            dead_before_read(image, decoder, target,
                             static_cast<unsigned>(selected.destination)) &&
            overwritten_stack_slot(image, decoder, *site, target);
      const auto branch = conditional_branch(selection, first, condition);
      const auto other = direct_branch(*transition.state_store, second);
      if (!removable || !branch || !other) {
        skip("compact comparison-tree terminator requires dead selected "
             "registers and private state storage");
        continue;
      }
      plan.edits.push_back(
          edit(image, *site, selection, *branch, first,
               "comparison-tree conditional edge; selected registers and "
               "private state store proven dead"));
      plan.edits.push_back(
          edit(image, *site, *transition.state_store, *other, second,
               "comparison-tree alternate edge replaces dead state store"));
      plan.edits.push_back(
          edit(image, *site, transition.arrival, 0xd503201f, {},
               "removed comparison-tree loopback after both direct edges"));
      continue;
    }
    if (flow.targets.size() == 1 || destinations.size() == 1) {
      auto target = *flow.targets[0].destination;
      auto branch = direct_branch(site->branch, target);
      if (!branch) {
        skip("direct branch is outside range");
        continue;
      }
      plan.edits.push_back(
          edit(image, *site, site->branch, *branch, target,
               "constant target; all preceding instructions preserved"));
      continue;
    }
    if (transition.predicate.is_null()) {
      skip("binary choice has no reusable predicate");
      continue;
    }
    auto first = *flow.targets[0].destination,
         second = *flow.targets[1].destination;
    auto kind = transition.predicate.at("kind").get<std::string>();
    auto selection = address_of_json(transition.predicate.at("selection"));
    if (kind == "condition" &&
        !quiet_flags(image, decoder, selection, site->branch)) {
      skip("condition flags were changed or crossed control flow");
      continue;
    }
    unsigned predicate_reg = 0, bit = 0, condition = 0;
    if (kind == "condition")
      condition = transition.predicate.at("condition");
    else if (kind == "bit") {
      predicate_reg = transition.predicate.at("register");
      bit = transition.predicate.at("bit");
      bool changed = false;
      for (Address cursor = selection + 4; cursor < site->branch; cursor += 4) {
        auto word = image.instruction(cursor);
        if (!word) {
          changed = true;
          break;
        }
        auto instruction = decoder.decode(cursor, *word);
        if (instruction.writes(predicate_reg) || instruction.control_transfer) {
          changed = true;
          break;
        }
      }
      if (changed) {
        skip("bit predicate register was overwritten");
        continue;
      }
    } else {
      skip("unsupported binary predicate");
      continue;
    }
    auto conditional = [&](Address from, Address to, bool inverted) {
      if (kind == "condition")
        return conditional_branch(from, to, condition ^ (inverted ? 1 : 0));
      return bit_branch(from, to, predicate_reg, bit, inverted);
    };
    if (first == site->branch + 4 || second == site->branch + 4) {
      bool inverted = first == site->branch + 4;
      auto target = inverted ? second : first;
      auto branch = conditional(site->branch, target, inverted);
      if (branch) {
        plan.edits.push_back(edit(image, *site, site->branch, *branch, target,
                                  "binary target with natural fallthrough"));
        continue;
      }
    }
    if (site->load_target + 4 != site->branch) {
      skip("two-slot branch requires adjacent target load and BR");
      continue;
    }
    if (site->target_reg < 0 ||
        !dead_before_read(image, decoder, first,
                          static_cast<unsigned>(site->target_reg)) ||
        !dead_before_read(image, decoder, second,
                          static_cast<unsigned>(site->target_reg))) {
      skip("removed target-load register remains live");
      continue;
    }
    auto first_branch = conditional(site->load_target, first, false),
         second_branch = direct_branch(site->branch, second);
    if (!first_branch || !second_branch) {
      skip("binary branches are outside range");
      continue;
    }
    plan.edits.push_back(
        edit(image, *site, site->load_target, *first_branch, first,
             "binary first target; target register proven dead"));
    plan.edits.push_back(edit(image, *site, site->branch, *second_branch,
                              second, "binary second target"));
  }
  std::map<Address, std::size_t> counts;
  for (auto [source, target] : graph) {
    if (++counts[source] > settings.maximum_targets)
      throw FlowError("resolved target count exceeds maximum_targets");
    plan.graph.push_back({source, target, false});
  }
  std::sort(plan.edits.begin(), plan.edits.end(),
            [](const auto &left, const auto &right) {
              return left.address < right.address;
            });
  for (std::size_t index = 1; index < plan.edits.size(); ++index)
    if (plan.edits[index - 1].address == plan.edits[index].address)
      throw FlowError("conflicting proposals at one instruction");
  return plan;
}
JsonDoc PatchPlan::json() const {
  JsonDoc changes = JsonDoc::array(), edges = JsonDoc::array();
  for (const auto &change : edits)
    changes.push_back(
        {{"address", format_address(change.address)},
         {"parent", format_address(change.parent)},
         {"site", format_address(change.site)},
         {"expected", hex_of_bytes(change.expected)},
         {"replacement", hex_of_bytes(change.replacement)},
         {"target", change.target ? JsonDoc(format_address(*change.target))
                                  : JsonDoc(nullptr)},
         {"reason", change.reason}});
  for (const auto &edge : graph)
    edges.push_back({{"source", format_address(edge.source)},
                     {"target", format_address(edge.target)}});
  return {{"schema_version", 1}, {"source_sha256", source_sha256},
          {"edits", changes},    {"skipped", skipped},
          {"graph", edges},      {"verification", "required_before_commit"}};
}
} // namespace armflow
