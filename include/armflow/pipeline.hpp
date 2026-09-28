#pragma once
#include <armflow/patching.hpp>
namespace armflow {
// Owns an immutable input. Every stage is regenerated from this image and the
// configuration; imported artifacts are evidence to check, never instructions.
class PipelineDriver {
public:
  PipelineDriver(BinaryImage input, JsonDoc configuration);
  JsonDoc stage(const std::string &name);
  void check_artifact(const JsonDoc &artifact);
  JsonDoc execute(const std::string &command, bool apply = false,
               const BinaryImage *candidate = nullptr);
  JsonDoc restore(const JsonDoc &receipt, const BinaryImage *current = nullptr);
  const BinaryImage &source() const { return input_; }
  const JsonDoc &configuration() const { return configuration_; }

private:
  JsonDoc envelope(const std::string &name) const;
  void analyze(unsigned depth);
  JsonDoc exercise();
  JsonDoc execute_batch(bool apply);
  PatchPlan effective_plan(const std::string &command) const;
  BinaryImage with_graph(BinaryImage candidate, const PatchPlan &plan,
                       JsonDoc &added) const;
  JsonDoc receipt(const std::string &command, const PatchPlan &plan,
               const BinaryImage &candidate, const JsonDoc &added, bool applied,
               const JsonDoc &verification) const;
  BinaryImage input_, analysis_image_;
  JsonDoc configuration_, executions_ = JsonDoc::array();
  JsonDoc expansion_ = JsonDoc::object(), table_graph_ = JsonDoc::object();
  FlowSettings settings_;
  OpcodeDecoder decoder_;
  std::string configuration_hash_, mode_;
  unsigned depth_ = 0;
  std::vector<SwitchSite> sites_;
  std::vector<BranchTransition> transitions_;
  std::vector<ResolvedBranch> flows_;
  SurveyObservations observations_;
  std::map<Address, std::map<std::uint64_t, std::set<Address>>> state_targets_;
  PatchPlan plan_;
  bool exercised_ = false;
};
} // namespace armflow
