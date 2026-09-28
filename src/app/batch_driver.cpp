#include <armflow/pipeline.hpp>
namespace armflow {
JsonDoc PipelineDriver::execute_batch(bool apply) {
  JsonDoc tasks = configuration_.value("jobs", JsonDoc::array());
  if (!tasks.is_array() || tasks.size() > 10000)
    throw FlowError(
        "jobs requires at most 10000 independent configurations");
  if (tasks.empty()) {
    analyze(1);
    std::map<Address, std::set<Address>> grouped;
    for (const auto &site : sites_)
      grouped[site.target_table.value_or(site.parent)].insert(site.parent);
    for (const auto &[key, entries] : grouped) {
      JsonDoc functions = JsonDoc::array();
      for (auto entry : entries)
        functions.push_back(format_address(entry));
      tasks.push_back({{"name", format_address(key)}, {"functions", functions}});
    }
  }
  auto report = envelope("batch");
  report["applied"] = apply;
  report["passed"] = true;
  report["groups"] = JsonDoc::array();
  report["semantics"] =
      "each group starts from the same source and returns its own receipt; "
      "candidates are not implicitly combined";
  for (std::size_t index = 0; index < tasks.size(); ++index) {
    const auto &task = tasks[index];
    JsonDoc row = {{"index", index}, {"passed", false}};
    try {
      if (!task.is_object())
        throw FlowError("job must be an object");
      for (const auto &[key, value] : task.items()) {
        (void)value;
        if (key != "name" && key != "functions" && key != "analysis" &&
            key != "execution" && key != "regression" && key != "mode")
          throw FlowError("unsupported job override: " + key);
      }
      auto local = configuration_;
      local.erase("jobs");
      auto overrides = task;
      overrides.erase("name");
      local.merge_patch(overrides);
      if (!local.contains("functions"))
        throw FlowError("each explicit job needs function selectors");
      row["name"] = task.value("name", std::to_string(index));
      PipelineDriver group(input_, local);
      row["configuration"] = group.configuration();
      row["analysis"] = group.stage("plan");
      row["result"] = group.execute("run", apply);
      row["passed"] = true;
    } catch (const std::exception &error) {
      row["error"] = error.what();
      report["passed"] = false;
    }
    report["groups"].push_back(std::move(row));
  }
  report["group_count"] = report["groups"].size();
  return report;
}
} // namespace armflow
