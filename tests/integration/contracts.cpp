#include <algorithm>
#include <armflow/patching.hpp>
#include <armflow/subprocess.hpp>
#include <fstream>
#include <iostream>
#include <unistd.h>
using namespace armflow;
namespace {
unsigned passed = 0, failed = 0;
void check(bool value, const std::string &message) {
  if (value)
    ++passed;
  else {
    ++failed;
    std::cerr << "FAIL: " << message << '\n';
  }
}
template <typename Function>
void rejects(Function action, const std::string &message) {
  try {
    action();
    check(false, message);
  } catch (const std::exception &) {
    check(true, message);
  }
}
JsonDoc parse(const std::string &text) {
  return document_of_bytes(
      {reinterpret_cast<const std::uint8_t *>(text.data()), text.size()});
}
ByteBuffer bytes(const std::string &text) { return {text.begin(), text.end()}; }
} // namespace
int main(int argc, char **argv) {
  if (argc > 1 && std::string(argv[1]) == "--echo") {
    std::cout << std::cin.rdbuf();
    return 0;
  }
  if (argc > 2 && std::string(argv[1]) == "--argument") {
    std::cout << argv[2];
    return 0;
  }
  if (argc > 1 && std::string(argv[1]) == "--sleep") {
    usleep(300000);
    return 0;
  }
  if (argc > 1 && std::string(argv[1]) == "--flood") {
    for (unsigned i = 0; i < 10000; ++i)
      std::cout << std::string(1000, 'x');
    return 0;
  }
  if (argc > 1 && std::string(argv[1]) == "--exit") {
    std::cerr << "expected failure";
    return 7;
  }
  if (argc > 1 && std::string(argv[1]) == "--wrong-receipt") {
    std::cout
        << R"({"protocol_version":1,"image_sha256":"wrong","entry":"0x0","completed":true})";
    return 0;
  }
  if (argc != 3)
    return 2;
  try {
    check(parse("{\"a\":1,\"nested\":{\"a\":2}}")["nested"]["a"] == 2,
          "same key in separate objects is legal");
    rejects([&] { parse("{\"a\":1,\"a\":2}"); }, "duplicate JSON key rejected");
    rejects([&] { parse(std::string(70, '[') + "0" + std::string(70, ']')); },
            "excessive JSON nesting rejected");
    rejects([&] { parse("{\"a\":1} {} "); }, "trailing JSON value rejected");
    ScratchDirectory temporary;
    auto document = temporary.path() / "report.json";
    store_document(document, {{"original", true}});
    rejects(
        [&] {
          store_document(document, {{"invalid", std::string(1, char(0xff))}});
        },
        "failed encoding rejects atomic write");
    check(load_document(document) == JsonDoc({{"original", true}}),
          "failed write preserves original document");
    store_document(document, {{"replacement", true}});
    check(load_document(document) == JsonDoc({{"replacement", true}}),
          "atomic replacement readable");
    check(std::distance(std::filesystem::directory_iterator(temporary.path()),
                        std::filesystem::directory_iterator{}) == 1,
          "temporary output files cleaned");
    auto yaml = temporary.path() / "config.yml";
    {
      std::ofstream stream(yaml);
      stream << "a: &cycle [*cycle]\n";
    }
    rejects([&] { load_document(yaml); }, "recursive YAML alias rejected");
    {
      std::ofstream stream(yaml);
      stream << "a: 1\na: 2\n";
    }
    rejects([&] { load_document(yaml); }, "duplicate YAML key rejected");
    ByteBuffer input(512 * 1024, 0x61);
    auto echo = spawn_process({argv[0], "--echo"}, input, 5000);
    check(echo.exit_code == 0 && echo.output == input,
          "bounded process drains output while feeding input");
    auto literal = std::string("space ' ; $HOME ");
    auto argument = spawn_process({argv[0], "--argument", literal}, {}, 5000);
    check(argument.output == bytes(literal),
          "arguments are not interpreted by a shell");
    auto exit = spawn_process({argv[0], "--exit"}, {}, 5000);
    check(exit.exit_code == 7 && exit.errors == bytes("expected failure"),
          "child status and stderr preserved");
    rejects([&] { spawn_process({argv[0], "--sleep"}, {}, 30); },
            "process timeout enforced");
    rejects([&] { spawn_process({argv[0], "--flood"}, {}, 5000, 1024); },
            "process output limit enforced");
    rejects([&] { spawn_process({"/no/such/armflow-worker"}, {}, 5000); },
            "missing process executable rejected");
    auto image = BinaryImage::load(argv[1]);
    OpcodeDecoder decoder;
    gather_direct_edges(image, decoder);
    JsonDoc selectors = JsonDoc::array();
    for (const auto &region : image.regions)
      if (region.executable)
        selectors.push_back({{"label", region.label}});
    auto settings =
        FlowSettings::from_json({{"executable_regions", selectors}}, image);
    auto sites = survey_switches(image, decoder, settings);
    auto transitions = classify_transitions(image, decoder, settings, sites);
    SurveyObservations none;
    auto flows = resolve_targets(image, settings, sites, transitions, none);
    auto plan = plan_patches(image, decoder, settings, sites, flows, none);
    for (const auto &site : sites)
      check(json_of_site(site_of_json(json_of_site(site))) ==
                json_of_site(site),
            "site artifact roundtrip");
    for (const auto &value : transitions)
      check(json_of_transition(transition_of_json(json_of_transition(value))) ==
                json_of_transition(value),
            "transition artifact roundtrip");
    for (const auto &value : flows)
      check(json_of_branch(branch_of_json(json_of_branch(value))) ==
                json_of_branch(value),
            "resolution artifact roundtrip");
    check(plan_of_json(plan.json()).json() == plan.json(),
          "plan artifact roundtrip");
    auto missing_target = plan;
    for (auto &edit : missing_target.edits)
      edit.target.reset();
    rejects([&] { PatchTransaction::prepare(image, missing_target); },
            "direct-branch edits must retain their decoded target metadata");
    auto unmapped_target = plan;
    unmapped_target.edits.resize(1);
    auto &unmapped_edit = unmapped_target.edits.front();
    const auto outside = image.regions.back().end() + 4096;
    unmapped_edit.replacement =
        word_bytes(*direct_branch(unmapped_edit.address, outside));
    unmapped_edit.target.reset();
    rejects(
        [&] { PatchTransaction::prepare(image, unmapped_target); },
        "omitting target metadata cannot admit a branch to unmapped memory");
    auto wrong = json_of_site(sites.front());
    wrong["state_register"] = 2.5;
    rejects([&] { site_of_json(wrong); }, "fractional register rejected");
    auto invalid = plan.json();
    invalid["edits"][0]["replacement"] = "00";
    rejects([&] { plan_of_json(invalid); }, "incorrect edit width rejected");
    auto unknown = json_of_transition(transitions.front());
    unknown["category"] = "invented";
    rejects([&] { transition_of_json(unknown); },
            "unknown transition category rejected");
    EmulationOracle direct({{"input", {{"mode", "scalar"}}}});
    EmulationOracle external(
        {{"backend", "command"}, {"command", JsonDoc::array({argv[2]})}});
    auto before = direct.run(image, image.entry, ByteBuffer{3}, sites);
    auto actual = external.run(image, image.entry, ByteBuffer{3}, sites);
    check(actual.output == before.output && actual.executed == before.executed,
          "external worker executes the supplied image with matching coverage");
    check(actual.observations.json() == before.observations.json(),
          "external branch observations agree");
    auto corrupted = image;
    corrupted.replace(image.entry + 36, word_bytes(0x91002000));
    auto altered = external.run(corrupted, image.entry, ByteBuffer{3}, sites);
    check(altered.output != actual.output,
          "external worker receives changed candidate bytes");
    EmulationOracle mismatched(
        {{"backend", "command"},
         {"command", JsonDoc::array({argv[0], "--wrong-receipt"})}});
    rejects([&] { mismatched.run(image, image.entry, ByteBuffer{3}); },
            "mismatched image receipt rejected");
    EmulationOracle raw({{"backend", "command"},
                         {"protocol", "bytes"},
                         {"command", JsonDoc::array({argv[0], "--echo"})}});
    rejects([&] { raw.run(image, image.entry, ByteBuffer{3}); },
            "raw oracle cannot omit candidate image argument");
    std::cout << passed << " boundary/IPC checks passed; " << failed
              << " failed\n";
    return failed ? 1 : 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
