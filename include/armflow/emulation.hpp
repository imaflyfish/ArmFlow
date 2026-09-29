#pragma once
#include <armflow/call_shims.hpp>
#include <armflow/flow_analysis.hpp>
namespace armflow {
JsonDoc gather_external_trace(const BinaryImage &image,
                              const JsonDoc &configuration);
struct EmulationResult {
  ByteBuffer output;
  std::uint64_t returned = 0, instructions = 0;
  SurveyObservations observations;
  std::set<Address> executed;
  std::map<Address, std::set<Address>> control_edges;
  std::map<Address, std::map<std::uint64_t, std::set<Address>>> state_targets;
};
JsonDoc json_of_execution(const EmulationResult &result);
EmulationResult execution_of_json(const JsonDoc &record,
                                  const BinaryImage &image);
class EmulationOracle {
public:
  explicit EmulationOracle(
      JsonDoc specification,
      std::shared_ptr<const ShimRegistry> registry = ShimRegistry::standard());
  EmulationResult run(const BinaryImage &image, Address entry,
                      std::span<const std::uint8_t> input,
                      const std::vector<SwitchSite> &sites = {}) const;
  JsonDoc compare(const BinaryImage &pristine, const BinaryImage &candidate,
                  const std::vector<SwitchSite> &sites = {}) const;

private:
  JsonDoc specification_;
  std::shared_ptr<const ShimRegistry> registry_;
};
} // namespace armflow
