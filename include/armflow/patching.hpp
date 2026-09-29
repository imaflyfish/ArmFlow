#pragma once
#include <armflow/emulation.hpp>
namespace armflow {
struct WordEdit {
  Address address = 0, parent = 0, site = 0;
  ByteBuffer expected, replacement;
  std::optional<Address> target;
  std::string reason;
};
struct PatchPlan {
  std::string source_sha256;
  std::vector<WordEdit> edits;
  JsonDoc skipped = JsonDoc::array();
  std::vector<FlowEdge> graph;
  JsonDoc json() const;
};
PatchPlan plan_of_json(const JsonDoc &record);
PatchPlan plan_filler_cleanup(const BinaryImage &image,
                              const OpcodeDecoder &decoder,
                              const FlowSettings &settings);
PatchPlan plan_patches(const BinaryImage &image, const OpcodeDecoder &decoder,
                       const FlowSettings &settings,
                       const std::vector<SwitchSite> &sites,
                       const std::vector<ResolvedBranch> &flows,
                       const SurveyObservations &observed);
JsonDoc extend_table_graph(const BinaryImage &image,
                           const FlowSettings &settings,
                           const std::vector<SwitchSite> &sites,
                           PatchPlan &plan);
JsonDoc verify_plan_expectations(const BinaryImage &candidate,
                                 const PatchPlan &plan,
                                 const JsonDoc &expectations);
class PatchTransaction {
public:
  static BinaryImage prepare(const BinaryImage &pristine,
                             const PatchPlan &plan);
  static JsonDoc commit(BinaryImage &current, const BinaryImage &pristine,
                        const PatchPlan &plan, const EmulationOracle &oracle);
  static void restore(BinaryImage &current, const BinaryImage &pristine,
                      const PatchPlan &plan);
  static JsonDoc self_check(const BinaryImage &candidate,
                            const PatchPlan &plan);
};
} // namespace armflow
