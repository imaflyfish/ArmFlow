#include <algorithm>
#include <armflow/patching.hpp>
#include <limits>
#include <set>
namespace armflow {
PatchPlan plan_filler_cleanup(const BinaryImage &image,
                              const OpcodeDecoder &decoder,
                              const FlowSettings &settings) {
  PatchPlan result;
  result.source_sha256 = image.fingerprint();
  const auto options = settings.raw.value("cleanup", JsonDoc::object());
  const auto maximum =
      address_of_json(options.value("maximum_filler_bytes", JsonDoc(8)));
  if (maximum < 4 || maximum > 64 || maximum % 4)
    throw FlowError(
        "cleanup filler limit must be a multiple of four within 4..64");
  std::set<Address> edited;
  auto valid = [&](Address address) {
    auto word = image.instruction(address);
    return word && decoder.decode(address, *word).valid;
  };
  auto filler = [&](Address address) {
    auto word = image.instruction(address);
    if (!word || decoder.decode(address, *word).valid)
      return false;
    const auto group = (*word >> 25) & 15;
    return group == 0 || group == 1 || group == 3;
  };
  auto append = [&](Address address, Address site, std::uint32_t word,
                    std::optional<Address> target, const std::string &reason) {
    auto function = image.function_at(address);
    if (!function || !settings.selects(address) ||
        !edited.insert(address).second)
      throw FlowError(
          "cleanup proposal lacks unique selected function ownership");
    result.edits.push_back({address, function->begin, site,
                            image.read(address, 4), word_bytes(word), target,
                            reason});
  };
  for (const auto &region : image.regions) {
    if (!region.executable)
      continue;
    for (Address address = region.begin + (4 - region.begin % 4) % 4;
         address < region.end() && region.end() - address >= 4; address += 4) {
      if (!settings.selects(address) || edited.contains(address))
        continue;
      auto function = image.function_at(address);
      if (!function)
        continue;
      const auto word = *image.instruction(address);
      if ((word & 0xff000000) == 0x58000000 && function->end - address >= 8 &&
          settings.selects(address + 4)) {
        const auto call = image.instruction(address + 4);
        if (call && (*call & 0xfffffc1f) == 0xd63f0000 &&
            ((*call >> 5) & 31) == (word & 31)) {
          const auto encoded = (word >> 5) & 0x7ffff;
          const auto distance = (static_cast<std::int64_t>(encoded & 0x3ffff) -
                                 static_cast<std::int64_t>(encoded & 0x40000)) *
                                4;
          std::optional<Address> target;
          if (distance < 0 && address >= static_cast<Address>(-distance))
            target = address - static_cast<Address>(-distance);
          else if (distance >= 0 &&
                   static_cast<Address>(distance) <=
                       std::numeric_limits<Address>::max() - address)
            target = address + static_cast<Address>(distance);
          bool entered = false;
          for (const auto &edge : image.references)
            if (edge.target == address + 4 && edge.source != address)
              entered = true;
          const auto branch =
              target ? direct_branch(address, *target) : std::nullopt;
          if (target && *target != address && *target != address + 4 &&
              valid(*target) && branch && !entered) {
            append(address, address, *branch, target,
                   "heuristic literal-load/BLR fold; behavior and coverage "
                   "verification required");
            append(address + 4, address, 0xd503201f, {},
                   "paired BLR slot; unverified cleanup proposal");
            result.graph.push_back({address, *target, false});
            continue;
          }
          result.skipped.push_back(
              {{"site", format_address(address)},
               {"reason", "literal/BLR target, alignment or interior entry "
                          "check failed"}});
        }
      }
      if (!filler(address) || address < function->begin + 4 ||
          !valid(address - 4))
        continue;
      Address end = address;
      while (end < function->end && end - address < maximum &&
             settings.selects(end) && filler(end))
        end += 4;
      if (end == address || end >= function->end || !valid(end))
        continue;
      for (auto slot = address; slot < end; slot += 4)
        append(slot, address, 0xd503201f, {},
               "heuristic short undecodable filler; no semantic claim until "
               "candidate verification");
      address = end - 4;
    }
  }
  std::sort(result.edits.begin(), result.edits.end(),
            [](const auto &a, const auto &b) { return a.address < b.address; });
  return result;
}
} // namespace armflow
