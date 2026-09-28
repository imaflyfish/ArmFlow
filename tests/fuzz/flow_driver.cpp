#include <armflow/patching.hpp>
namespace {
void exercise(armflow::BinaryImage image) {
  using namespace armflow;
  std::size_t size = 0;
  FlowSettings settings;
  for (const auto &region : image.regions) {
    size += region.bytes.size();
    if (region.executable)
      settings.ranges.emplace_back(region.begin, region.end());
  }
  if (size > 65536 || image.functions.size() > 64)
    return;
  settings.lookback = 16;
  settings.raw["analysis"]["state_expansion"] = {{"maximum_states", 16},
                                                 {"maximum_steps", 512}};
  OpcodeDecoder decoder;
  gather_direct_edges(image, decoder);
  auto sites = survey_switches(image, decoder, settings);
  auto transitions = classify_transitions(image, decoder, settings, sites);
  SurveyObservations none;
  auto flows = resolve_targets(image, settings, sites, transitions, none);
  expand_states(image, decoder, settings, sites, flows, none);
  auto plan = plan_patches(image, decoder, settings, sites, flows, none);
  extend_table_graph(image, settings, sites, plan);
  PatchTransaction::prepare(image, plan);
  PatchTransaction::prepare(image, plan_filler_cleanup(image, decoder, settings));
}
} // namespace
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data,
                                      std::size_t size) {
  using namespace armflow;
  if (size > 65536)
    return 0;
  if (size && (data[0] == '{' || data[0] == '[')) {
    try {
      const auto document = document_of_bytes({data, size});
      try {
        BinaryImage::from_flat({data, size}, document);
      } catch (const std::exception &) {
      }
      try {
        exercise(BinaryImage::from_snapshot(document));
      } catch (const std::exception &) {
      }
      try {
        site_of_json(document);
      } catch (const std::exception &) {
      }
      try {
        transition_of_json(document);
      } catch (const std::exception &) {
      }
      try {
        branch_of_json(document);
      } catch (const std::exception &) {
      }
      try {
        plan_of_json(document);
      } catch (const std::exception &) {
      }
    } catch (const std::exception &) {
    }
  }
  try {
    exercise(BinaryImage::from_elf({data, size}));
  } catch (const std::exception &) {
  }
  if (size < 4)
    return 0;
  try {
    BinaryImage image;
    ImageRegion region;
    region.begin = 0x100000;
    region.bytes.assign(data, data + size - size % 4);
    region.executable = true;
    image.regions.push_back(region);
    image.functions.push_back({region.begin, region.end(), "fuzz"});
    OpcodeDecoder decoder;
    for (Address address = region.begin; address < region.end(); address += 4)
      decoder.decode(address, *image.instruction(address));
    ConstantWalker tracker(image, decoder, 16, 4);
    tracker.resolve(region.end(), data[0] % 32, 32);
    tracker.resolve(region.end(), data[1] % 32, 64);
    exercise(std::move(image));
  } catch (const std::exception &) {
  }
  return 0;
}
