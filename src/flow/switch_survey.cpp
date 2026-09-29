#include <algorithm>
#include <armflow/flow_analysis.hpp>
#include <deque>
#include <limits>
namespace armflow {
namespace {
std::optional<DecodedWord> instruction_at(const BinaryImage &image,
                                          const OpcodeDecoder &decoder,
                                          Address address) {
  auto word = image.instruction(address);
  return word ? std::optional<DecodedWord>(decoder.decode(address, *word))
              : std::nullopt;
}
std::optional<Address> materialized_base(const BinaryImage &image,
                                         const OpcodeDecoder &decoder,
                                         const ConstantWalker &tracker,
                                         Address use, int reg) {
  if (reg < 0 || reg > 30)
    return {};
  auto direct = tracker.resolve(use, static_cast<unsigned>(reg), 64);
  if (direct && direct->singleton())
    return direct->values[0];
  // A value defined in the straight-line entry prefix dominates the remaining
  // function only when the register has no later writes and there is no
  // external entry.
  auto function = image.function_at(use);
  if (!function)
    return {};
  Address boundary = function->begin;
  for (; boundary < use; boundary += 4) {
    auto decoded = instruction_at(image, decoder, boundary);
    if (!decoded || !decoded->valid)
      return {};
    if (decoded->control_transfer)
      break;
  }
  if (boundary == use)
    return {};
  auto prefix = tracker.resolve(boundary, static_cast<unsigned>(reg), 64);
  if (!prefix || !prefix->singleton())
    return {};
  for (Address current = boundary; current < function->end; current += 4) {
    auto decoded = instruction_at(image, decoder, current);
    if (!decoded || !decoded->valid ||
        decoded->writes(static_cast<unsigned>(reg)))
      return {};
  }
  for (const auto &edge : image.references)
    if (edge.target > function->begin && edge.target <= use &&
        (edge.source < function->begin || edge.source >= function->end))
      return {};
  return prefix->values[0];
}
void identify_parent(SwitchSite &site, const BinaryImage &image) {
  if (auto function = image.function_at(site.branch)) {
    site.parent = function->begin;
    site.parent_end = function->end;
  } else if (auto region = image.region_at(site.branch)) {
    site.parent = region->begin;
    site.parent_end = region->end();
  }
}
std::optional<Address> state_load(const BinaryImage &image,
                                  const OpcodeDecoder &decoder,
                                  const ConstantWalker &tracker, Address use,
                                  int reg, const FlowSettings &settings) {
  auto producer = tracker.producer(use, static_cast<unsigned>(reg));
  if (!producer)
    return {};
  auto decoded = instruction_at(image, decoder, *producer);
  if (!decoded || decoded->operation != Mnemonic::load || !decoded->memory ||
      decoded->memory->index != -1 ||
      !settings.state_bases.contains(
          static_cast<unsigned>(decoded->memory->base)))
    return {};
  return producer;
}
void arrivals(SwitchSite &site, const BinaryImage &image,
              const OpcodeDecoder &decoder) {
  for (const auto &edge : image.references)
    if (edge.target == site.head)
      site.arrivals.push_back(edge.source);
  if (site.head >= site.parent + 4) {
    auto preceding = instruction_at(image, decoder, site.head - 4);
    if (preceding && (!preceding->control_transfer ||
                      preceding->operation == Mnemonic::conditional_branch ||
                      preceding->operation == Mnemonic::compare_branch ||
                      preceding->operation == Mnemonic::bit_branch))
      site.arrivals.push_back(site.head);
  }
  if (site.arrivals.empty())
    site.arrivals.push_back(site.head);
  std::sort(site.arrivals.begin(), site.arrivals.end());
  site.arrivals.erase(std::unique(site.arrivals.begin(), site.arrivals.end()),
                      site.arrivals.end());
  for (const auto &edge : image.references)
    if (edge.target > site.head && edge.target <= site.branch &&
        (edge.source < site.head || edge.source >= site.branch))
      site.detail["interior_entry"] = true;
}
std::vector<SwitchSite> comparison_sites(const BinaryImage &image,
                                         const OpcodeDecoder &decoder,
                                         const FlowSettings &settings) {
  std::vector<SwitchSite> result;
  ConstantWalker tracker(image, decoder, settings.lookback);
  for (const auto &function : image.functions) {
    std::map<Address, unsigned> incoming;
    for (const auto &edge : image.references)
      if (edge.source >= function.begin && edge.source < function.end &&
          edge.target >= function.begin && edge.target < function.end &&
          edge.target < edge.source)
        ++incoming[edge.target];
    for (auto [head, count] : incoming) {
      (void)count;
      if (!settings.selects(head))
        continue;
      auto load = instruction_at(image, decoder, head);
      if (!load || load->operation != Mnemonic::load || !load->memory ||
          load->memory->index != -1 ||
          !settings.state_bases.contains(
              static_cast<unsigned>(load->memory->base)) ||
          load->memory->width != 4)
        continue;
      SwitchSite site;
      site.model = "comparison_tree";
      site.branch = head;
      site.head = head;
      site.load_state = head;
      site.state_reg = load->destination;
      site.state_slot = load->memory;
      site.parent = function.begin;
      site.parent_end = function.end;
      std::deque<Address> pending{head + 4};
      std::set<Address> visited;
      unsigned budget = 1024;
      while (!pending.empty() && budget) {
        Address position = pending.front();
        pending.pop_front();
        while (position >= function.begin && position < function.end &&
               budget > 0) {
          --budget;
          if (!visited.insert(position).second)
            break;
          auto current = instruction_at(image, decoder, position);
          if (!current || !current->valid)
            break;
          if (current->operation == Mnemonic::branch && current->target) {
            if (*current->target != head)
              pending.push_back(*current->target);
            break;
          }
          if (current->operation != Mnemonic::compare ||
              current->left != site.state_reg)
            break;
          std::optional<std::uint64_t> magic = current->immediate;
          if (!magic && current->right >= 0)
            magic = materialized_base(image, decoder, tracker, position,
                                      current->right);
          if (magic && !current->immediate && current->shift) {
            if (current->shift >= current->width || current->shift_kind > 1)
              magic.reset();
            else if (current->shift_kind == 0)
              *magic <<= current->shift;
            else
              *magic >>= current->shift;
          }
          if (magic && current->width == 32)
            *magic &= 0xffffffff;
          if (!magic)
            break;
          Address jump_position = position + 4;
          std::optional<DecodedWord> jump;
          for (unsigned skip = 0; skip < 6 && jump_position < function.end;
               ++skip, jump_position += 4) {
            auto candidate = instruction_at(image, decoder, jump_position);
            if (!candidate || !candidate->valid)
              break;
            if (candidate->operation == Mnemonic::conditional_branch) {
              jump = candidate;
              break;
            }
            if (candidate->flags_written || candidate->control_transfer ||
                candidate->operation != Mnemonic::nop)
              break;
          }
          if (!jump || !jump->target)
            break;
          auto target = *jump->target;
          if (!image.valid_target(target))
            break;
          if (jump->condition == 0)
            site.comparisons[*magic] = target;
          else if (jump->condition == 1)
            site.comparisons[*magic] = jump_position + 4;
          if (site.comparisons.size() > settings.maximum_targets)
            throw FlowError(
                "comparison-tree target count exceeds maximum_targets");
          if (jump->condition != 0 && target != head)
            pending.push_back(target);
          if (jump->condition == 1)
            break;
          position = jump_position + 4;
        }
      }
      if (site.comparisons.empty())
        continue;
      // A shape alone is not enough: route each inferred state through the
      // actual comparison conditions, including earlier BST bounds.
      auto route = [&](std::uint64_t state) -> std::optional<Address> {
        std::set<Address> handlers;
        for (const auto &[value, handler] : site.comparisons) {
          (void)value;
          handlers.insert(handler);
        }
        Address position = head + 4;
        std::set<Address> walked;
        std::optional<unsigned> flags;
        std::uint64_t loaded = state & 0xffffffff;
        if (site.state_slot->signed_value && (loaded & 0x80000000))
          loaded |= 0xffffffff00000000;
        for (unsigned steps = 0; steps < 1024; ++steps) {
          if (position < function.begin || position >= function.end ||
              !walked.insert(position).second)
            return {};
          if (handlers.contains(position))
            return position;
          const auto current = instruction_at(image, decoder, position);
          if (!current || !current->valid)
            return {};
          if (current->operation == Mnemonic::nop) {
            position += 4;
            continue;
          }
          if (current->operation == Mnemonic::branch && current->target) {
            position = *current->target;
            continue;
          }
          if (current->operation == Mnemonic::compare &&
              current->left == site.state_reg) {
            auto right = current->immediate;
            if (!right && current->right >= 0)
              right = materialized_base(image, decoder, tracker, position,
                                        current->right);
            if (!right)
              return {};
            if (!current->immediate && current->shift) {
              if (current->shift >= current->width || current->shift_kind > 1)
                return {};
              if (current->shift_kind == 0)
                *right <<= current->shift;
              else
                *right >>= current->shift;
            }
            const auto mask = current->width == 32 ? std::uint64_t{0xffffffff}
                                                   : ~std::uint64_t{0};
            const auto left = loaded & mask, operand = *right & mask,
                       value = (left - operand) & mask;
            const auto sign = std::uint64_t{1} << (current->width - 1);
            flags = ((value & sign) ? 8u : 0u) | (value == 0 ? 4u : 0u) |
                    (left >= operand ? 2u : 0u) |
                    (((left ^ operand) & (left ^ value) & sign) ? 1u : 0u);
            position += 4;
            continue;
          }
          if (current->operation != Mnemonic::conditional_branch ||
              !current->target || !flags || current->condition >= 14)
            return {};
          const bool n = *flags & 8, z = *flags & 4, c = *flags & 2,
                     v = *flags & 1;
          bool take = false;
          switch (current->condition >> 1) {
          case 0:
            take = z;
            break;
          case 1:
            take = c;
            break;
          case 2:
            take = n;
            break;
          case 3:
            take = v;
            break;
          case 4:
            take = c && !z;
            break;
          case 5:
            take = n == v;
            break;
          case 6:
            take = !z && n == v;
            break;
          default:
            return {};
          }
          if (current->condition & 1)
            take = !take;
          position = take ? *current->target : position + 4;
        }
        return {};
      };
      std::vector<std::uint64_t> rejected;
      for (const auto &[state, handler] : site.comparisons)
        if (route(state) != handler)
          rejected.push_back(state);
      for (auto state : rejected)
        site.comparisons.erase(state);
      if (site.comparisons.empty())
        continue;
      site.detail["unproven_comparison_states"] = rejected;
      site.detail["analysis"] = "experimental comparison-tree recovery";
      arrivals(site, image, decoder);
      result.push_back(std::move(site));
    }
  }
  return result;
}
} // namespace
FlowSettings FlowSettings::from_json(const JsonDoc &document,
                                     const BinaryImage &image) {
  FlowSettings settings;
  settings.raw = document;
  auto analysis = document.value("analysis", JsonDoc::object());
  const auto lookback =
      address_of_json(analysis.value("lookback", JsonDoc(128u)));
  const auto maximum_targets =
      address_of_json(analysis.value("maximum_targets", JsonDoc(256u)));
  settings.single_level = analysis.value("single_level", true);
  settings.comparison_tree = analysis.value("comparison_tree", true);
  if (!lookback || lookback > 4096 || !maximum_targets ||
      maximum_targets > 65536)
    throw FlowError("analysis limit outside allowed range");
  auto registers = [&](const std::string &key,
                       std::set<unsigned> &destination) {
    if (!analysis.contains(key))
      return;
    const auto &values = analysis.at(key);
    if (!values.is_array() || values.size() > 32)
      throw FlowError(key + " must be an array of register numbers");
    destination.clear();
    for (const auto &value : values) {
      const auto number = address_of_json(value);
      if (number > 31)
        throw FlowError(key + " contains an invalid register");
      destination.insert(static_cast<unsigned>(number));
    }
  };
  registers("state_bases", settings.state_bases);
  registers("index_registers", settings.index_registers);
  settings.lookback = static_cast<unsigned>(lookback);
  settings.maximum_targets = static_cast<unsigned>(maximum_targets);
  if (!document.contains("executable_regions") ||
      !document["executable_regions"].is_array() ||
      document["executable_regions"].empty())
    throw FlowError(
        "executable_regions must explicitly select at least one region");
  for (const auto &selector : document["executable_regions"]) {
    if (selector.contains("label")) {
      bool found = false;
      for (const auto &region : image.regions)
        if (region.label == selector["label"].get<std::string>() &&
            region.executable) {
          settings.ranges.emplace_back(region.begin, region.end());
          found = true;
        }
      if (!found)
        throw FlowError("executable region label did not match");
    } else if (selector.contains("range")) {
      auto bounds = selector["range"];
      if (!bounds.is_array() || bounds.size() != 2)
        throw FlowError("region range requires two addresses");
      auto start = address_of_json(bounds[0]), end = address_of_json(bounds[1]);
      if (start >= end || start % 4 || end % 4 ||
          end - start > 256 * 1024 * 1024)
        throw FlowError("invalid executable range");
      auto region =
          image.region_at(start, static_cast<std::size_t>(end - start));
      if (!region || !region->executable)
        throw FlowError("selected range is not executable");
      settings.ranges.emplace_back(start, end);
    } else
      throw FlowError("region selector requires label or range");
  }
  for (const auto &row : analysis.value("table_overrides", JsonDoc::array())) {
    auto site = address_of_json(row.at("site"));
    if (row.contains("index"))
      settings.index_overrides[site] = address_of_json(row["index"]);
    if (row.contains("target"))
      settings.target_overrides[site] = address_of_json(row["target"]);
  }
  return settings;
}
bool FlowSettings::selects(Address address) const {
  return std::any_of(ranges.begin(), ranges.end(), [&](const auto &range) {
    return address >= range.first && address < range.second;
  });
}
void gather_direct_edges(BinaryImage &image, const OpcodeDecoder &decoder) {
  std::set<std::pair<Address, Address>> known;
  for (const auto &edge : image.references)
    known.emplace(edge.source, edge.target);
  for (const auto &region : image.regions)
    if (region.executable)
      for (Address address = region.begin + (4 - region.begin % 4) % 4;
           address < region.end() && region.end() - address >= 4;
           address += 4) {
        auto decoded = decoder.decode(address, *image.instruction(address));
        if (decoded.control_transfer && !decoded.call && decoded.target &&
            known.emplace(address, *decoded.target).second)
          image.references.push_back({address, *decoded.target, false});
      }
}
std::vector<SwitchSite> survey_switches(const BinaryImage &image,
                                        const OpcodeDecoder &decoder,
                                        const FlowSettings &settings) {
  std::vector<SwitchSite> result;
  ConstantWalker tracker(image, decoder, settings.lookback);
  for (const auto &region : image.regions)
    if (region.executable)
      for (Address address = region.begin + (4 - region.begin % 4) % 4;
           address < region.end() && region.end() - address >= 4;
           address += 4) {
        if (!settings.selects(address))
          continue;
        auto branch = decoder.decode(address, *image.instruction(address));
        if (branch.operation != Mnemonic::indirect_branch || branch.left < 0)
          continue;
        auto producer =
            tracker.producer(address, static_cast<unsigned>(branch.left));
        if (!producer)
          continue;
        auto target = instruction_at(image, decoder, *producer);
        if (!target || target->operation != Mnemonic::load || !target->memory ||
            target->memory->width != 8 || target->memory->index < 0)
          continue;
        SwitchSite site;
        site.model = "single_level";
        site.branch = address;
        site.load_target = *producer;
        site.head = *producer;
        site.target_reg = branch.left;
        site.target_base = target->memory->base;
        site.target_access = target->memory;
        site.state_reg = target->memory->index;
        identify_parent(site, image);
        site.target_table = materialized_base(image, decoder, tracker,
                                              *producer, site.target_base);
        auto index_producer = tracker.producer(
            *producer, static_cast<unsigned>(target->memory->index));
        if (index_producer) {
          auto index = instruction_at(image, decoder, *index_producer);
          if (index && index->operation == Mnemonic::load && index->memory &&
              index->memory->signed_value && index->memory->width == 4 &&
              index->memory->index >= 0 && index->memory->scale == 2 &&
              target->memory->scale == 3) {
            site.model = "two_level";
            site.load_index = *index_producer;
            site.index_access = index->memory;
            site.index_base = index->memory->base;
            site.state_reg = index->memory->index;
            site.index_table = materialized_base(
                image, decoder, tracker, *index_producer, site.index_base);
            site.head = *index_producer;
            site.load_state =
                state_load(image, decoder, tracker, *index_producer,
                           site.state_reg, settings);
            if (site.load_state) {
              auto state = instruction_at(image, decoder, *site.load_state);
              site.state_slot = state->memory;
              site.head = *site.load_state;
            }
          }
        }
        if (!settings.index_registers.empty() &&
            !settings.index_registers.contains(
                static_cast<unsigned>(site.state_reg)))
          continue;
        if (site.model == "single_level" && !settings.single_level)
          continue;
        if (settings.target_overrides.contains(site.branch))
          site.target_table = settings.target_overrides.at(site.branch);
        if (settings.index_overrides.contains(site.branch))
          site.index_table = settings.index_overrides.at(site.branch);
        arrivals(site, image, decoder);
        result.push_back(std::move(site));
      }
  if (settings.comparison_tree) {
    auto trees = comparison_sites(image, decoder, settings);
    result.insert(result.end(), trees.begin(), trees.end());
  }
  std::sort(result.begin(), result.end(),
            [](const auto &left, const auto &right) {
              return left.branch < right.branch;
            });
  return result;
}
} // namespace armflow
