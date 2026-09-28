#include <armflow/patching.hpp>
namespace armflow {
JsonDoc verify_plan_expectations(const BinaryImage &candidate,
                             const PatchPlan &plan,
                             const JsonDoc &expectations) {
  if (!expectations.is_object())
    throw FlowError("regression expectations require an object");
  JsonDoc rows = JsonDoc::array();
  bool passed = true;
  auto record = [&](const std::string &name, bool ok, JsonDoc detail) {
    rows.push_back(
        {{"name", name}, {"passed", ok}, {"detail", std::move(detail)}});
    passed = passed && ok;
  };
  if (expectations.contains("minimum_edits")) {
    auto minimum = address_of_json(expectations.at("minimum_edits"));
    record("minimum_edits", plan.edits.size() >= minimum,
           {{"expected", minimum}, {"actual", plan.edits.size()}});
  }
  if (expectations.contains("maximum_skips")) {
    auto maximum = address_of_json(expectations.at("maximum_skips"));
    record("maximum_skips", plan.skipped.size() <= maximum,
           {{"expected", maximum}, {"actual", plan.skipped.size()}});
  }
  if (expectations.contains("expected_skips")) {
    const auto &expected = expectations.at("expected_skips");
    if (!expected.is_array() || expected.size() > 100000)
      throw FlowError("expected_skips must be a bounded array");
    auto normalize = [](const JsonDoc &values) {
      std::set<std::tuple<Address, Address, std::string>> out;
      for (const auto &value : values) {
        const auto site = address_of_json(value.at("site"));
        const auto arrival =
            value.contains("arrival") ? address_of_json(value.at("arrival")) : 0;
        const auto reason = value.at("reason").get<std::string>();
        if (!out.emplace(site, arrival, reason).second)
          throw FlowError("duplicate expected skip");
      }
      return out;
    };
    record("expected_skips", normalize(expected) == normalize(plan.skipped),
           {{"expected", expected}, {"actual", plan.skipped}});
  }
  const auto samples = expectations.value("instruction_samples", JsonDoc::array());
  if (!samples.is_array() || samples.size() > 10000)
    throw FlowError("instruction_samples must be a bounded array");
  OpcodeDecoder decoder;
  for (const auto &sample : samples) {
    const auto address = address_of_json(sample.at("address"));
    const auto word = candidate.instruction(address);
    bool ok = word.has_value();
    if (!sample.contains("word") && !sample.contains("operation") &&
        !sample.contains("target"))
      throw FlowError("instruction sample has no expectation");
    JsonDoc actual = {{"address", format_address(address)}};
    if (word) {
      const auto view = decoder.decode(address, *word);
      actual["word"] = format_address(*word);
      actual["operation"] = mnemonic_name(view.operation);
      actual["target"] =
          view.target ? JsonDoc(format_address(*view.target)) : JsonDoc(nullptr);
      ok = view.valid;
      if (sample.contains("word"))
        ok = ok && *word == address_of_json(sample.at("word"));
      if (sample.contains("operation"))
        ok = ok && mnemonic_name(view.operation) ==
                       sample.at("operation").get<std::string>();
      if (sample.contains("target"))
        ok = ok && view.target &&
             *view.target == address_of_json(sample.at("target"));
    }
    record("instruction_sample", ok,
           {{"expected", sample}, {"actual", actual}});
  }
  return {{"passed", passed}, {"checks", rows}};
}
} // namespace armflow
