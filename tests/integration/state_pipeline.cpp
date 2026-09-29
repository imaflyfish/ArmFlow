#include <armflow/pipeline.hpp>
#include <iostream>
using namespace armflow;
namespace {
unsigned passed = 0, failed = 0;
void check(bool ok, const std::string &name) {
  if (ok)
    ++passed;
  else {
    ++failed;
    std::cerr << "FAIL: " << name << '\n';
  }
}
template <class F> void rejects(F action, const std::string &name) {
  try {
    action();
    check(false, name);
  } catch (const std::exception &) {
    check(true, name);
  }
}
Address named(const BinaryImage &i, const std::string &name) {
  for (const auto &f : i.functions)
    if (f.label == name)
      return f.begin;
  throw FlowError("missing function");
}
} // namespace
int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  try {
    const auto image = BinaryImage::load(argv[1]);
    JsonDoc config = {
        {"executable_regions", JsonDoc::array({{{"label", "load_0"}}})},
        {"mode", "linear"},
        {"functions", JsonDoc::array({"state_chain"})}};
    auto analysis = PipelineDriver(image, config).stage("plan");
    check(analysis.at("sites").size() == 1, "two-level state chain identified");
    unsigned transforms = 0;
    for (const auto &flow : analysis.at("flows")) {
      if (flow.at("transition").at("category") == "transform")
        ++transforms;
      (void)branch_of_json(flow);
    }
    check(transforms == 2,
          "both arithmetic/bitwise chains classified as transforms");
    const auto &expanded = analysis.at("state_expansion");
    check(!expanded.at("truncated").get<bool>() &&
              expanded.at("sites")[0].at("state_count") == 3,
          "bounded expansion discovers the closed three-state chain");
    check(expanded.at("sites")[0].at("states") ==
              JsonDoc::array({"0x0", "0x1", "0x3"}),
          "operation order and 32-bit arithmetic yield states 0,3,1");
    check(expanded.at("sites")[0].at("transitions").size() == 2,
          "expansion follows only reachable transform bodies");
    auto plan = plan_of_json(analysis.at("plan"));
    check(plan.edits.empty() && plan.graph.size() == 3,
          "scrambler and shared branch remain intact while all derived edges "
          "are reported");
    OpcodeDecoder decoder;
    auto analyzed = image;
    gather_direct_edges(analyzed, decoder);
    auto settings = FlowSettings::from_json(config, analyzed);
    auto sites = survey_switches(analyzed, decoder, settings);
    auto execution =
        EmulationOracle(JsonDoc::object())
            .run(image, named(image, "state_chain"), ByteBuffer{5}, sites);
    check(execution.returned == 42,
          "independent machine execution traverses both state transforms");
    for (const auto &edge : plan.graph)
      check(execution.observations.targets[edge.source].contains(edge.target),
            "derived graph edge agrees with actual Unicorn execution");
    config["analysis"] = {{"state_expansion", {{"enabled", false}}},
                          {"graph_tables", {{"enabled", false}}}};
    auto disabled = PipelineDriver(image, config).stage("plan");
    check(
        !disabled.at("state_expansion").at("enabled").get<bool>() &&
            disabled.at("plan").at("graph").size() == 1,
        "explicitly disabling expansion keeps only original constant evidence");
    config["analysis"]["state_expansion"] = {{"maximum_states", 1}};
    auto capped =
        PipelineDriver(image, config).stage("resolve").at("state_expansion");
    check(capped.at("truncated").get<bool>() &&
              capped.at("sites")[0].at("state_count") == 1,
          "state cap is explicit and no extra state is admitted");
    config["analysis"]["state_expansion"] = {{"maximum_steps", 1}};
    capped =
        PipelineDriver(image, config).stage("resolve").at("state_expansion");
    check(capped.at("truncated").get<bool>() && capped.at("steps_used") == 1,
          "step budget cannot silently become complete");
    config["analysis"]["state_expansion"] = {{"maximum_states", 1.5}};
    rejects([&] { PipelineDriver(image, config).stage("resolve"); },
            "fractional state cap rejected");
    const auto state_site =
        address_of_json(analysis.at("sites")[0].at("branch"));
    config["analysis"]["state_expansion"] = {
        {"seed_states", {{"0x1234", JsonDoc::array({1})}}}};
    rejects([&] { PipelineDriver(image, config).stage("resolve"); },
            "unrecognized seed site is rejected");
    config["analysis"]["state_expansion"] = {
        {"seed_states",
         {{format_address(state_site), JsonDoc::array({"0x100000000"})}}}};
    rejects([&] { PipelineDriver(image, config).stage("resolve"); },
            "explicit seed cannot exceed a 32-bit state slot");
    config["analysis"] = JsonDoc::object();
    config["functions"] = JsonDoc::array({"state_cycle"});
    auto cycle =
        PipelineDriver(image, config).stage("resolve").at("state_expansion");
    check(!cycle.at("truncated").get<bool>() &&
              cycle.at("sites")[0].at("states") ==
                  JsonDoc::array({"0x0", "0x1"}),
          "cyclic state graph reaches a finite fixed point");
    rejects(
        [&] {
          EmulationOracle({{"maximum_instructions", 1000}})
              .run(image, named(image, "state_cycle"), {});
        },
        "finite analysis does not claim an infinite program returns");
    config["functions"] = JsonDoc::array({"state_wrap"});
    auto wrapped = PipelineDriver(image, config).stage("plan");
    check(wrapped.at("state_expansion").at("sites")[0].at("states") ==
              JsonDoc::array({"0x0", "0xffffffff"}),
          "subtraction wraps as 32-bit state with signed table indexing");
    execution =
        EmulationOracle(JsonDoc::object())
            .run(image, named(image, "state_wrap"), ByteBuffer{7}, sites);
    check(execution.returned == 7, "signed state table remains executable");
    const auto wrap_site = site_of_json(wrapped.at("sites")[0]);
    check(execution.state_targets.at(wrap_site.branch).contains(0xffffffff),
          "LDRSW observation is normalized to the stored 32-bit state");
    config["analysis"] = {{"emulate", true}};
    config["execution"] = {
        {"known_vectors",
         JsonDoc::array({{{"entry", format_address(named(image, "state_wrap"))},
                          {"input", "07"},
                          {"output", "0700000000000000"}}})}};
    auto observed = PipelineDriver(image, config).stage("resolve");
    for (const auto &flow : observed.at("flows"))
      for (const auto &target : flow.at("targets"))
        check(
            target.at("evidence") == "observed",
            "expanded wrap target is cross-checked against natural execution");
    std::cout << passed << " state-expansion checks passed; " << failed
              << " failed\n";
    return failed ? 1 : 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
