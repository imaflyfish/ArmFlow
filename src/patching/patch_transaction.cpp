#include <armflow/patching.hpp>
#include <set>
namespace armflow {
BinaryImage PatchTransaction::prepare(const BinaryImage &pristine,
                                      const PatchPlan &plan) {
  pristine.validate();
  if (pristine.fingerprint() != plan.source_sha256)
    throw FlowError(
        "plan source fingerprint does not match the original image");
  std::set<Address> seen;
  for (const auto &edit : plan.edits) {
    if (edit.address % 4 || edit.expected.size() != 4 ||
        edit.replacement.size() != 4 || !pristine.instruction(edit.address))
      throw FlowError("edit must replace one mapped instruction");
    if (!seen.insert(edit.address).second)
      throw FlowError("overlapping edits");
    if (pristine.read(edit.address, 4) != edit.expected)
      throw FlowError("recorded original instruction does not match");
    if (auto function = pristine.function_at(edit.address);
        !function || function->begin != edit.parent)
      throw FlowError("edit lacks matching function ownership");
  }
  auto candidate = pristine;
  for (const auto &edit : plan.edits)
    candidate.replace(edit.address, edit.replacement);
  auto checks = self_check(candidate, plan);
  if (!checks["passed"].get<bool>())
    throw FlowError("candidate instruction self-check failed");
  return candidate;
}
JsonDoc PatchTransaction::commit(BinaryImage &current,
                                 const BinaryImage &pristine,
                                 const PatchPlan &plan,
                                 const EmulationOracle &oracle) {
  auto candidate = prepare(pristine, plan);
  auto current_hash = current.fingerprint();
  if (current_hash != candidate.fingerprint() &&
      current_hash != pristine.fingerprint())
    throw FlowError("current image changed; no edits were committed");
  auto evidence = oracle.compare(pristine, candidate);
  if (!evidence.at("passed").get<bool>())
    throw FlowError("candidate failed before/after known-vector comparison");
  std::set<Address> covered;
  for (const auto &vector : evidence.at("vectors"))
    for (const auto &address : vector.at("original_coverage"))
      covered.insert(address_of_json(address));
  for (const auto &edit : plan.edits)
    if (!covered.contains(edit.address))
      throw FlowError(
          "known vectors did not execute every edited original instruction");
  SurveyObservations observed;
  for (const auto &vector : evidence.at("vectors"))
    observed.merge(vector.at("original_observations"));
  std::set<Address> modified_sites;
  for (const auto &edit : plan.edits)
    modified_sites.insert(edit.site);
  for (auto site : modified_sites) {
    auto word = pristine.instruction(site);
    if (!word || (*word & 0xfffffc1f) != 0xd61f0000)
      continue;
    std::set<Address> expected;
    for (const auto &edge : plan.graph)
      if (edge.source == site)
        expected.insert(edge.target);
    if (expected.empty() || observed.targets[site] != expected)
      throw FlowError(
          "known vectors did not cover the complete proposed target set");
  }
  std::map<Address, std::set<Address>> executed_edges;
  for (const auto &vector : evidence.at("vectors"))
    for (const auto &[source, destinations] :
         vector.at("candidate_control_edges").items())
      for (const auto &target : destinations)
        executed_edges[address_of_json(JsonDoc(source))].insert(
            address_of_json(target));
  OpcodeDecoder decoder;
  for (const auto &edit : plan.edits) {
    const auto instruction =
        decoder.decode(edit.address, *candidate.instruction(edit.address));
    if (!instruction.target || !instruction.control_transfer)
      continue;
    std::set<Address> required{*instruction.target};
    if (instruction.operation == Mnemonic::conditional_branch ||
        instruction.operation == Mnemonic::compare_branch ||
        instruction.operation == Mnemonic::bit_branch)
      required.insert(edit.address + 4);
    if (executed_edges[edit.address] != required)
      throw FlowError(
          "known vectors did not execute every candidate branch outcome");
  }
  current = std::move(candidate);
  return evidence;
}
void PatchTransaction::restore(BinaryImage &current,
                               const BinaryImage &pristine,
                               const PatchPlan &plan) {
  auto candidate = prepare(pristine, plan);
  auto fingerprint = current.fingerprint();
  if (fingerprint == pristine.fingerprint())
    return;
  if (fingerprint != candidate.fingerprint())
    throw FlowError(
        "current image is neither the recorded original nor candidate");
  current = pristine;
}
JsonDoc PatchTransaction::self_check(const BinaryImage &candidate,
                                     const PatchPlan &plan) {
  OpcodeDecoder decoder;
  JsonDoc rows = JsonDoc::array();
  bool passed = true;
  for (const auto &edit : plan.edits) {
    auto word = candidate.instruction(edit.address);
    bool okay = word && candidate.read(edit.address, 4) == edit.replacement;
    std::optional<DecodedWord> instruction;
    if (word)
      instruction = decoder.decode(edit.address, *word);
    okay = okay && instruction && instruction->valid &&
           (!edit.target || instruction->target == edit.target);
    if (instruction &&
        (instruction->operation == Mnemonic::branch ||
         instruction->operation == Mnemonic::call ||
         instruction->operation == Mnemonic::conditional_branch ||
         instruction->operation == Mnemonic::compare_branch ||
         instruction->operation == Mnemonic::bit_branch))
      // Direct branches cannot evade target validation by dropping the optional
      // metadata field. The decoded destination must be recorded and mapped.
      okay =
          okay && edit.target.has_value() && instruction->target == edit.target;
    if (edit.target)
      okay = okay && candidate.valid_target(*edit.target);
    rows.push_back(
        {{"address", format_address(edit.address)}, {"passed", okay}});
    passed = passed && okay;
  }
  return {{"passed", passed}, {"instructions", rows}};
}
} // namespace armflow
