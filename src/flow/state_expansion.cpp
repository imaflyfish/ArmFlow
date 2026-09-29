#include <algorithm>
#include <armflow/flow_analysis.hpp>
#include <deque>
namespace armflow {
namespace {
bool reaches_reload(const BinaryImage &image, const OpcodeDecoder &decoder,
                    const SwitchSite &site, Address begin,
                    const BranchTransition &transition, std::uint64_t &budget) {
  const auto source = address_of_json(transition.transform.at("source"));
  std::deque<std::pair<Address, bool>> pending{{begin, false}};
  std::set<std::pair<Address, bool>> visited;
  while (!pending.empty() && budget) {
    auto [address, loaded] = pending.front();
    pending.pop_front();
    while (budget) {
      --budget;
      if (address < site.parent || address >= site.parent_end ||
          !visited.emplace(address, loaded).second)
        break;
      if (address == transition.arrival) {
        if (loaded)
          return true;
        break;
      }
      if (address == site.head)
        break;
      const auto word = image.instruction(address);
      if (!word)
        break;
      const auto instruction = decoder.decode(address, *word);
      if (!instruction.valid || instruction.call ||
          instruction.operation == Mnemonic::return_)
        break;
      if (address == source)
        loaded = true;
      if (site.state_slot &&
          instruction.writes(static_cast<unsigned>(site.state_slot->base)))
        break;
      if (!loaded && instruction.operation == Mnemonic::store) {
        if (!instruction.memory || !site.state_slot)
          break;
        const auto &memory = *instruction.memory;
        const auto &slot = *site.state_slot;
        if (memory.base != slot.base || memory.index >= 0 || memory.writeback ||
            !memory.width ||
            (memory.displacement < slot.displacement + 4 &&
             memory.displacement + static_cast<std::int64_t>(memory.width) >
                 slot.displacement))
          break;
      }
      // A store which the manual model does not understand may alias the state.
      if (!loaded && instruction.observable &&
          instruction.operation == Mnemonic::unknown)
        break;
      if (instruction.operation == Mnemonic::branch) {
        if (!instruction.target)
          break;
        address = *instruction.target;
        continue;
      }
      if (instruction.operation == Mnemonic::conditional_branch ||
          instruction.operation == Mnemonic::compare_branch ||
          instruction.operation == Mnemonic::bit_branch) {
        if (!instruction.target)
          break;
        pending.emplace_back(*instruction.target, loaded);
      } else if (instruction.control_transfer)
        break;
      address += 4;
    }
  }
  return false;
}
std::uint64_t transform(std::uint64_t input, const JsonDoc &description) {
  const auto &operations = description.at("operations_reverse");
  if (!operations.is_array() || operations.empty() || operations.size() > 16)
    throw FlowError("invalid bounded state transform");
  auto value = input & 0xffffffff;
  for (auto operation = operations.rbegin(); operation != operations.rend();
       ++operation) {
    const auto name = operation->at("operation").get<std::string>();
    const auto immediate = address_of_json(operation->at("immediate"));
    if (name == "add")
      value += immediate;
    else if (name == "subtract")
      value -= immediate;
    else if (name == "xor")
      value ^= immediate;
    else if (name == "and")
      value &= immediate;
    else if (name == "or")
      value |= immediate;
    else
      throw FlowError("unsupported state transform operation");
    value &= 0xffffffff;
  }
  return value;
}
} // namespace
JsonDoc expand_states(
    const BinaryImage &image, const OpcodeDecoder &decoder,
    const FlowSettings &settings, const std::vector<SwitchSite> &sites,
    std::vector<ResolvedBranch> &flows, const SurveyObservations &observed,
    const std::map<Address, std::map<std::uint64_t, std::set<Address>>>
        &traced_states) {
  const auto options = settings.raw.value("analysis", JsonDoc::object())
                           .value("state_expansion", JsonDoc::object());
  if (!options.is_object())
    throw FlowError("state_expansion requires an object");
  if (!options.value("enabled", true))
    return {{"enabled", false}};
  const auto maximum =
      address_of_json(options.value("maximum_states", JsonDoc(256)));
  auto budget =
      address_of_json(options.value("maximum_steps", JsonDoc(100000)));
  if (!maximum || maximum > 65536 || !budget || budget > 1000000)
    throw FlowError("state expansion budget is outside its bounds");
  const auto extra = options.value("seed_states", JsonDoc::object());
  if (!extra.is_object() || extra.size() > 10000)
    throw FlowError(
        "state expansion seed_states requires a bounded site-to-array map");
  std::map<Address, std::set<std::uint64_t>> supplied;
  for (const auto &[key, values] : extra.items()) {
    const auto address = address_of_json(JsonDoc(key));
    const auto site =
        std::find_if(sites.begin(), sites.end(), [&](const auto &candidate) {
          return candidate.branch == address;
        });
    if (site == sites.end() || supplied.contains(address))
      throw FlowError(
          "seed states refer to an unknown or duplicate dispatch site");
    if (!values.is_array() || values.size() > 65536)
      throw FlowError("seed states require at most 65536 integers");
    auto &states = supplied[address];
    for (const auto &value : values) {
      const auto state = address_of_json(value);
      if (state > 0xffffffff && site->state_slot &&
          site->state_slot->width == 4)
        throw FlowError("seed state exceeds its 32-bit slot");
      states.insert(state);
    }
  }
  const auto initial_budget = budget;
  JsonDoc report = {{"enabled", true},
                    {"maximum_states", maximum},
                    {"maximum_steps", budget},
                    {"truncated", false},
                    {"sites", JsonDoc::array()}};
  for (const auto &site : sites) {
    std::vector<std::size_t> transforms;
    std::set<std::uint64_t> seeds;
    for (std::size_t index = 0; index < flows.size(); ++index) {
      const auto &flow = flows[index];
      if (flow.transition.branch != site.branch)
        continue;
      if (flow.transition.category == "transform" &&
          !flow.transition.transform.is_null())
        transforms.push_back(index);
      if (flow.transition.state)
        for (auto state : flow.transition.state->values)
          seeds.insert(state);
    }
    if (transforms.empty())
      continue;
    if (auto found = traced_states.find(site.branch);
        found != traced_states.end())
      for (const auto &[state, targets] : found->second) {
        (void)targets;
        seeds.insert(state);
      }
    if (const auto found = supplied.find(site.branch); found != supplied.end())
      seeds.insert(found->second.begin(), found->second.end());
    JsonDoc row = {{"site", format_address(site.branch)},
                   {"transitions", JsonDoc::array()},
                   {"unresolved", JsonDoc::array()},
                   {"truncated", false}};
    std::set<std::uint64_t> admitted;
    std::deque<std::uint64_t> pending;
    auto admit = [&](std::uint64_t state) {
      if (admitted.contains(state))
        return true;
      if (admitted.size() >= maximum) {
        row["truncated"] = true;
        report["truncated"] = true;
        return false;
      }
      admitted.insert(state);
      pending.push_back(state);
      return true;
    };
    for (auto state : seeds)
      admit(state);
    auto target_for = [&](std::uint64_t state) {
      BranchTransition probe;
      probe.branch = site.branch;
      probe.category = "constant";
      probe.state = ConstantFact{{state}, {}, {}, {}};
      auto record = resolve_targets(image, settings, {site}, {probe}, observed)
                        .front()
                        .targets.front();
      if (auto found = traced_states.find(site.branch);
          found != traced_states.end()) {
        const auto at_state = found->second.find(state);
        if (at_state != found->second.end() && !at_state->second.empty()) {
          if (at_state->second.size() != 1 ||
              (record.destination &&
               !at_state->second.contains(*record.destination))) {
            record.evidence = "conflict";
            record.reason = "state-specific execution disagrees";
          } else if (!record.destination) {
            record.destination = *at_state->second.begin();
            record.evidence = image.valid_target(*record.destination)
                                  ? "emulated"
                                  : "invalid";
            record.reason = "state-specific execution supplied the target";
          }
        }
      }
      return record;
    };
    while (!pending.empty() && budget) {
      --budget;
      const auto state = pending.front();
      pending.pop_front();
      const auto destination = target_for(state);
      if (!destination.destination || destination.evidence == "invalid" ||
          destination.evidence == "conflict") {
        row["unresolved"].push_back({{"state", format_address(state)},
                                     {"reason", destination.reason},
                                     {"evidence", destination.evidence}});
        continue;
      }
      for (auto index : transforms) {
        auto &flow = flows[index];
        if (!reaches_reload(image, decoder, site, *destination.destination,
                            flow.transition, budget))
          continue;
        const auto next = transform(state, flow.transition.transform);
        if (!admit(next))
          continue;
        auto resolved = target_for(next);
        const auto earlier =
            std::find_if(flow.targets.begin(), flow.targets.end(),
                         [&](const auto &t) { return t.state == next; });
        if (earlier == flow.targets.end()) {
          resolved.reason =
              "bounded transform from " + format_address(state) +
              (resolved.reason.empty() ? "" : "; " + resolved.reason);
          flow.targets.push_back(resolved);
        }
        row["transitions"].push_back(
            {{"arrival", format_address(flow.transition.arrival)},
             {"input_state", format_address(state)},
             {"output_state", format_address(next)},
             {"destination", resolved.destination ? JsonDoc(format_address(
                                                        *resolved.destination))
                                                  : JsonDoc(nullptr)},
             {"evidence", resolved.evidence}});
      }
    }
    if (!pending.empty() || budget == 0) {
      row["truncated"] = true;
      report["truncated"] = true;
    }
    row["states"] = JsonDoc::array();
    for (auto state : admitted)
      row["states"].push_back(format_address(state));
    row["state_count"] = admitted.size();
    report["sites"].push_back(std::move(row));
    if (!budget)
      break;
  }
  for (auto &flow : flows)
    if (flow.transition.category == "transform")
      std::sort(flow.targets.begin(), flow.targets.end(),
                [](const auto &a, const auto &b) { return a.state < b.state; });
  report["steps_used"] = initial_budget - budget;
  report["semantics"] = "bounded candidate-state propagation; transform byte "
                        "edits remain disabled";
  return report;
}
} // namespace armflow
