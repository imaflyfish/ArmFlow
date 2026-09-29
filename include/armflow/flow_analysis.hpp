#pragma once
#include <armflow/opcode.hpp>
#include <map>
#include <set>
namespace armflow {
struct FlowSettings {
  unsigned lookback = 128, maximum_targets = 256;
  bool single_level = true, comparison_tree = true;
  std::set<unsigned> state_bases{29, 31}, index_registers;
  std::vector<std::pair<Address, Address>> ranges;
  std::map<Address, Address> index_overrides, target_overrides;
  JsonDoc raw = JsonDoc::object();
  static FlowSettings from_json(const JsonDoc &document,
                                const BinaryImage &image);
  bool selects(Address address) const;
};
struct SwitchSite {
  std::string model;
  Address branch = 0, head = 0, load_target = 0, parent = 0, parent_end = 0;
  std::optional<Address> load_index, load_state, index_table, target_table;
  int target_reg = -1, state_reg = -1, index_base = -1, target_base = -1;
  std::optional<MemoryAccess> state_slot, index_access, target_access;
  std::vector<Address> arrivals;
  std::map<std::uint64_t, Address> comparisons;
  JsonDoc detail = JsonDoc::object();
};
struct BranchTransition {
  Address branch = 0, arrival = 0;
  std::optional<Address> state_store;
  std::string category = "unknown", reason;
  std::optional<ConstantFact> state;
  JsonDoc predicate = nullptr;
  JsonDoc transform = nullptr;
};
struct TargetEntry {
  std::uint64_t state = 0;
  std::optional<std::int64_t> index;
  std::optional<Address> destination;
  std::string evidence = "invalid", reason;
};
struct ResolvedBranch {
  BranchTransition transition;
  std::vector<TargetEntry> targets;
};
struct SurveyObservations {
  std::map<Address, std::set<Address>> targets;
  void merge(const JsonDoc &document);
  std::string grade(Address site, Address target) const;
  bool multiple(Address site) const;
  JsonDoc json() const;
};
void gather_direct_edges(BinaryImage &image, const OpcodeDecoder &decoder);
std::vector<SwitchSite> survey_switches(const BinaryImage &image,
                                        const OpcodeDecoder &decoder,
                                        const FlowSettings &settings);
std::vector<BranchTransition>
classify_transitions(const BinaryImage &image, const OpcodeDecoder &decoder,
                     const FlowSettings &settings,
                     const std::vector<SwitchSite> &sites);
std::vector<ResolvedBranch>
resolve_targets(const BinaryImage &image, const FlowSettings &settings,
                const std::vector<SwitchSite> &sites,
                const std::vector<BranchTransition> &transitions,
                const SurveyObservations &observed);
JsonDoc expand_states(
    const BinaryImage &image, const OpcodeDecoder &decoder,
    const FlowSettings &settings, const std::vector<SwitchSite> &sites,
    std::vector<ResolvedBranch> &flows, const SurveyObservations &observed,
    const std::map<Address, std::map<std::uint64_t, std::set<Address>>>
        &traced_states = {});
SwitchSite site_of_json(const JsonDoc &record);
BranchTransition transition_of_json(const JsonDoc &record);
ResolvedBranch branch_of_json(const JsonDoc &record);
JsonDoc json_of_site(const SwitchSite &value);
JsonDoc json_of_transition(const BranchTransition &value);
JsonDoc json_of_branch(const ResolvedBranch &value);
} // namespace armflow
