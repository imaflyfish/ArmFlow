#include <armflow/flow_analysis.hpp>
namespace armflow {
namespace {
JsonDoc address(const std::optional<Address> &value) {
  return value ? JsonDoc(format_address(*value)) : JsonDoc(nullptr);
}
JsonDoc memory(const std::optional<MemoryAccess> &value) {
  if (!value)
    return nullptr;
  return {{"base", value->base},
          {"index", value->index},
          {"displacement", value->displacement},
          {"width", value->width},
          {"scale", value->scale},
          {"extension", value->extension},
          {"signed", value->signed_value},
          {"writeback", value->writeback}};
}
} // namespace
JsonDoc json_of_site(const SwitchSite &value) {
  JsonDoc arrivals = JsonDoc::array(), comparisons = JsonDoc::object();
  for (auto item : value.arrivals)
    arrivals.push_back(format_address(item));
  for (auto [state, target] : value.comparisons)
    comparisons[format_address(state)] = format_address(target);
  return {{"model", value.model},
          {"branch", format_address(value.branch)},
          {"head", format_address(value.head)},
          {"target_load", format_address(value.load_target)},
          {"index_load", address(value.load_index)},
          {"state_load", address(value.load_state)},
          {"parent", format_address(value.parent)},
          {"parent_end", format_address(value.parent_end)},
          {"target_table", address(value.target_table)},
          {"index_table", address(value.index_table)},
          {"target_register", value.target_reg},
          {"state_register", value.state_reg},
          {"index_base_register", value.index_base},
          {"target_base_register", value.target_base},
          {"state_slot", memory(value.state_slot)},
          {"index_access", memory(value.index_access)},
          {"target_access", memory(value.target_access)},
          {"arrivals", arrivals},
          {"comparisons", comparisons},
          {"detail", value.detail}};
}
JsonDoc json_of_transition(const BranchTransition &value) {
  JsonDoc state = nullptr;
  if (value.state) {
    JsonDoc values = JsonDoc::array(), producers = JsonDoc::array();
    for (auto entry : value.state->values)
      values.push_back(format_address(entry));
    for (auto entry : value.state->producers)
      producers.push_back(format_address(entry));
    state = {{"values", values},
             {"producers", producers},
             {"condition", value.state->condition
                               ? JsonDoc(*value.state->condition)
                               : JsonDoc(nullptr)},
             {"selection", address(value.state->selection)}};
  }
  return {{"branch", format_address(value.branch)},
          {"arrival", format_address(value.arrival)},
          {"state_store", address(value.state_store)},
          {"category", value.category},
          {"state", state},
          {"predicate", value.predicate},
          {"transform", value.transform},
          {"reason", value.reason}};
}
JsonDoc json_of_branch(const ResolvedBranch &value) {
  JsonDoc targets = JsonDoc::array();
  for (const auto &target : value.targets)
    targets.push_back(
        {{"state", format_address(target.state)},
         {"index", target.index ? JsonDoc(*target.index) : JsonDoc(nullptr)},
         {"destination", address(target.destination)},
         {"evidence", target.evidence},
         {"reason", target.reason}});
  return {{"transition", json_of_transition(value.transition)},
          {"targets", targets}};
}
} // namespace armflow
