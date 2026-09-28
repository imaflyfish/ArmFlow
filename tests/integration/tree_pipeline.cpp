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
  throw FlowError("missing function: " + name);
}
std::string scalar(std::uint64_t x) {
  ByteBuffer b(8);
  for (unsigned i = 0; i < 8; ++i)
    b[i] = static_cast<std::uint8_t>(x >> (i * 8));
  return hex_of_bytes(b);
}
} // namespace
int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  try {
    const auto image = BinaryImage::load(argv[1]);
    OpcodeDecoder decoder;
    const std::vector<std::pair<std::string, unsigned>> functions = {
        {"tree_compact", 4},       {"tree_padding", 3},
        {"tree_fallthrough", 2},   {"tree_live_slot", 1},
        {"tree_escaped_slot", 1},  {"tree_live_register", 1},
        {"tree_changed_flags", 1}, {"tree_live_flags", 1},
        {"tree_callee_saved", 1}};
    for (const auto &[name, count] : functions) {
      JsonDoc vectors = JsonDoc::array();
      for (unsigned input : {0u, 1u, 7u}) {
        const auto expected = name == "tree_live_slot" ||
                                      name == "tree_live_register" ||
                                      name == "tree_callee_saved"
                                  ? (input == 0 ? 1u : 2u)
                              : name == "tree_live_flags" ? 1u
                              : input == 0                ? 11u
                                                          : 23u;
        vectors.push_back(
            {{"entry", format_address(named(image, name == "tree_callee_saved"
                                                    ? "tree_callee_observer"
                                                    : name))},
             {"input", scalar(input)},
             {"output", scalar(expected)}});
      }
      JsonDoc config = {
          {"executable_regions", JsonDoc::array({{{"label", "load_0"}}})},
          {"mode", "linear"},
          {"functions", JsonDoc::array({name})},
          {"execution", {{"known_vectors", vectors}}}};
      PipelineDriver workflow(image, config);
      auto analysis = workflow.stage("plan");
      check(analysis.at("sites").size() == 1 &&
                analysis.at("sites")[0].at("model") == "comparison_tree",
            "recognize comparison model: " + name);
      auto plan = plan_of_json(analysis.at("plan"));
      check(plan.edits.size() == count,
            "exact conditional rewrite/refusal count: " + name);
      if (plan.edits.size() != count)
        std::cerr << analysis.dump(2) << '\n';
      auto before = image;
      auto verification = PatchTransaction::commit(
          before, image, plan, EmulationOracle(config.at("execution")));
      check(verification.at("passed").get<bool>(),
            "actual original/candidate vectors: " + name);
      if (count > 1) {
        auto one = config.at("execution");
        one["known_vectors"] = JsonDoc::array({vectors[0]});
        auto unmodified = image;
        rejects(
            [&] {
              PatchTransaction::commit(unmodified, image, plan,
                                         EmulationOracle(one));
            },
            "one observed path cannot certify binary tree rewrite: " + name);
        check(unmodified.fingerprint() == image.fingerprint(),
              "incomplete path verification leaves original unchanged");
        auto corrupted = PatchTransaction::prepare(image, plan);
        for (const auto &edit : plan.edits) {
          const auto instruction = decoder.decode(
              edit.address, *corrupted.instruction(edit.address));
          if (instruction.operation == Mnemonic::conditional_branch) {
            corrupted.replace(
                edit.address,
                word_bytes(*corrupted.instruction(edit.address) ^ 1));
            break;
          }
        }
        check(!EmulationOracle(config.at("execution"))
                   .compare(image, corrupted)
                   .at("passed")
                   .get<bool>(),
              "inverted candidate predicate is actually rejected");
      } else
        check(!analysis.at("plan").at("skipped").empty(),
              "unsafe conditional has explicit skip evidence: " + name);
      PatchTransaction::restore(before, image, plan);
      check(before.fingerprint() == image.fingerprint(),
            "tree rewrite restores exact source");
      check(workflow.execute("regress").at("passed").get<bool>(),
            "workflow regenerates tree plan and skips: " + name);
    }
    JsonDoc config = {{"executable_regions", JsonDoc::array({{{"label", "load_0"}}})},
                   {"functions", JsonDoc::array({"tree_bst_bounds"})}};
    auto analysis = PipelineDriver(image, config).stage("survey");
    check(analysis.at("sites").size() == 1, "BST fixture recognized");
    const auto site = site_of_json(analysis.at("sites")[0]);
    check(site.comparisons.contains(1) && site.comparisons.contains(2) &&
              !site.comparisons.contains(3),
          "earlier BST bounds reject a superficially matching unreachable "
          "equality");
    check(site.detail.at("unproven_comparison_states") == JsonDoc::array({3}),
          "contradictory comparison is explicitly reported");
    std::cout << passed << " tree checks passed; " << failed << " failed\n";
    return failed ? 1 : 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
