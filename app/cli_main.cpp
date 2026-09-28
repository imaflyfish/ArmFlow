#include <armflow/pipeline.hpp>
#include <iostream>
#include <map>
#include <set>
using namespace armflow;
namespace {
const char *help = R"(ArmFlow — AArch64 analysis and verified rewriting
  arm-flow COMMAND --image IMAGE --config CONFIG [OPTIONS]
  arm-flow snapshot IMAGE [OUTPUT]
  arm-flow decode WORD [ADDRESS]
Commands:
  survey, classify, resolve, plan  Generate source-bound analysis stages
  preview, run                    Candidate image (run --apply to apply)
  graph                           Graph edges (use --apply to apply)
  cleanup                         Propose literal/BLR and short filler changes
  trace                           Execute and observe known vectors
  verify                          Verify proposed or --current candidate
  regress                         Verify, restore, and regenerate all proposals
  restore                         Restore a matching applied --from receipt
  discover                        Group work by function
  batch                           Independent per-group results (optional --apply)
Options:
  --output FILE     Atomically write JSON (otherwise stdout)
  --from FILE       Check a prior stage artifact; required for restore
  --current FILE    Current snapshot/result envelope for verify or restore
  --function NAME   Select a function entry address or unambiguous name
  --apply           Return an applied snapshot; preserve all input files
  --dry-run         Explicit preview; incompatible with --apply
IMAGE may be set as `image` in CONFIG, relative to that file.
CONFIG: JSON/YAML, executable_regions, mode (default graph), analysis,
observations/trace_files, execution and known_vectors.
Aliases: census=survey, apply=run, switch=graph, revert=restore, clean=cleanup.
The apply alias still needs --apply to apply changes to the output snapshot.
Exit: 0 completed, 1 verification failed, 2 invalid input/execution error.
)";
struct CliArguments {
  std::string command;
  std::map<std::string, std::string> values;
  bool apply = false, dry = false;
};
CliArguments arguments(int argc, char **argv) {
  CliArguments result;
  result.command = argv[1];
  const std::map<std::string, std::string> aliases{{"census", "survey"},
                                                   {"apply", "run"},
                                                   {"switch", "graph"},
                                                   {"revert", "restore"},
                                                   {"clean", "cleanup"}};
  if (auto found = aliases.find(result.command); found != aliases.end())
    result.command = found->second;
  const std::set<std::string> options{"--image", "--config",  "--output",
                                      "--from",  "--current", "--function"};
  std::set<std::string> seen;
  for (int index = 2; index < argc; ++index) {
    const std::string key = argv[index];
    if (!seen.insert(key).second)
      throw FlowError("duplicate option: " + key);
    if (key == "--apply")
      result.apply = true;
    else if (key == "--dry-run")
      result.dry = true;
    else if (options.contains(key)) {
      if (++index == argc)
        throw FlowError("missing value for " + key);
      result.values[key] = argv[index];
    } else
      throw FlowError("unknown option: " + key);
  }
  if (result.apply && result.dry)
    throw FlowError("--apply and --dry-run are mutually exclusive");
  if (!result.values.contains("--config"))
    throw FlowError("--config is required");
  const std::set<std::string> commands{
      "survey", "classify", "resolve", "plan", "preview", "run", "graph",
      "cleanup", "trace", "verify", "regress", "restore", "discover", "batch"};
  if (!commands.contains(result.command))
    throw FlowError("unknown workflow command: " + result.command);
  if (result.values.contains("--current") && result.command != "verify" &&
      result.command != "restore")
    throw FlowError("--current is only valid for verify and restore");
  if (result.command == "restore" && !result.values.contains("--from"))
    throw FlowError("restore requires --from an applied receipt");
  if (result.apply && result.command != "run" && result.command != "graph" &&
      result.command != "cleanup" && result.command != "batch")
    throw FlowError("--apply is only valid for run, graph, cleanup and batch");
  return result;
}
std::filesystem::path resolved(const std::filesystem::path &path,
                               const std::filesystem::path &base) {
  return std::filesystem::weakly_canonical(path.is_absolute() ? path
                                                              : base / path);
}
void guard_output(const std::filesystem::path &output,
                  const std::vector<std::filesystem::path> &inputs) {
  const auto canonical = std::filesystem::weakly_canonical(output);
  for (const auto &input : inputs) {
    if (canonical == std::filesystem::weakly_canonical(input))
      throw FlowError(
          "output must not replace an input or configuration file");
    std::error_code error;
    if (std::filesystem::exists(output) &&
        std::filesystem::equivalent(output, input, error) && !error)
      throw FlowError("output aliases an input file");
  }
}
BinaryImage load_current(const std::filesystem::path &path) {
  auto bytes = load_file(path);
  if (bytes.size() >= 4 && bytes[0] == 0x7f && bytes[1] == 'E' &&
      bytes[2] == 'L' && bytes[3] == 'F')
    return BinaryImage::from_elf(bytes);
  auto document = load_document(path);
  return BinaryImage::from_snapshot(
      document.contains("image") ? document.at("image") : document);
}
int run(int argc, char **argv) {
  if (argc == 1 || std::string(argv[1]) == "--help") {
    std::cout << help;
    return argc == 1 ? 2 : 0;
  }
  if (std::string(argv[1]) == "--version" && argc == 2) {
    std::cout << "ArmFlow 1.0.0\n";
    return 0;
  }
  const std::string command = argv[1];
  if (command == "snapshot" && (argc == 3 || argc == 4)) {
    auto image = BinaryImage::load(argv[2]);
    if (argc == 4) {
      guard_output(argv[3], {argv[2]});
      store_document(argv[3], image.snapshot());
    } else
      std::cout << image.snapshot().dump(2) << '\n';
    return 0;
  }
  if (command == "decode" && (argc == 3 || argc == 4)) {
    auto raw = address_of_json(JsonDoc(argv[2]));
    if (raw > 0xffffffff)
      throw FlowError("instruction exceeds 32 bits");
    auto address = argc == 4 ? address_of_json(JsonDoc(argv[3])) : 0x100000;
    OpcodeDecoder decoder;
    const auto instruction =
        decoder.decode(address, static_cast<std::uint32_t>(raw));
    std::cout << JsonDoc({{"address", format_address(address)},
                       {"word", format_address(raw)},
                       {"valid", instruction.valid},
                       {"operation", mnemonic_name(instruction.operation)},
                       {"text", instruction.text},
                       {"width", instruction.width},
                       {"destination", instruction.destination},
                       {"left", instruction.left},
                       {"right", instruction.right},
                       {"condition", instruction.condition},
                       {"flags_written", instruction.flags_written},
                       {"flags_read", instruction.flags_read},
                       {"written_registers", instruction.written.to_string()},
                       {"target", instruction.target
                                      ? JsonDoc(format_address(*instruction.target))
                                      : JsonDoc(nullptr)},
                       {"immediate",
                        instruction.immediate
                            ? JsonDoc(format_address(*instruction.immediate))
                            : JsonDoc(nullptr)}})
                     .dump(2)
              << '\n';
    return instruction.valid ? 0 : 1;
  }
  auto options = arguments(argc, argv);
  auto config_path =
      resolved(options.values.at("--config"), std::filesystem::current_path());
  auto config = load_document(config_path);
  std::vector<std::filesystem::path> inputs{config_path};
  auto image_path = options.values.contains("--image")
                        ? resolved(options.values.at("--image"),
                                   std::filesystem::current_path())
                        : resolved(config.at("image").get<std::string>(),
                                   config_path.parent_path());
  inputs.push_back(image_path);
  auto input_image =
      config.contains("flat")
          ? BinaryImage::from_flat(load_file(image_path), config.at("flat"))
          : BinaryImage::load(image_path);
  input_image.origin = image_path.string();
  config.erase("image");
  if (config.contains("trace_files")) {
    SurveyObservations combined;
    if (config.contains("observations"))
      combined.merge(config.at("observations"));
    const auto traces = config.at("trace_files");
    if (!traces.is_array() || traces.size() > 256)
      throw FlowError("trace_files requires at most 256 paths");
    for (const auto &trace : traces) {
      auto path = resolved(trace.get<std::string>(), config_path.parent_path());
      inputs.push_back(path);
      auto document = load_document(path);
      if (document.contains("source_sha256") &&
          document.at("source_sha256").get<std::string>() !=
              input_image.fingerprint())
        throw FlowError("trace artifact belongs to a different image");
      combined.merge(document.contains("observations")
                         ? document.at("observations")
                         : document);
    }
    config["observations"] = combined.json();
    config.erase("trace_files");
  }
  if (options.values.contains("--function"))
    config["functions"] = JsonDoc::array({options.values.at("--function")});
  if (config.contains("execution") && config["execution"].contains("command")) {
    auto &argv_list = config["execution"]["command"];
    if (!argv_list.is_array() || argv_list.empty())
      throw FlowError("execution.command requires a nonempty argv array");
    auto program = argv_list[0].get<std::string>();
    if (program.find('/') != std::string::npos)
      argv_list[0] = resolved(program, config_path.parent_path()).string();
  }
  if (config.contains("trace_command")) {
    auto &argv_list = config["trace_command"]["argv"];
    if (!argv_list.is_array() || argv_list.empty())
      throw FlowError("trace_command.argv requires a nonempty argv array");
    const auto program = argv_list[0].get<std::string>();
    if (program.find('/') != std::string::npos)
      argv_list[0] = resolved(program, config_path.parent_path()).string();
  }
  std::optional<JsonDoc> prior;
  if (options.values.contains("--from")) {
    inputs.push_back(options.values.at("--from"));
    prior = load_document(options.values.at("--from"));
  }
  std::optional<BinaryImage> current;
  if (options.values.contains("--current")) {
    inputs.push_back(options.values.at("--current"));
    current = load_current(options.values.at("--current"));
  }
  if (options.values.contains("--output"))
    guard_output(options.values.at("--output"), inputs);
  // Construction may launch a user-configured trace program. Reject malformed
  // requests and protected output paths before allowing that external work.
  PipelineDriver workflow(std::move(input_image), config);
  if (prior && options.command != "restore")
    workflow.check_artifact(*prior);
  JsonDoc output;
  if (options.command == "restore") {
    output = workflow.restore(*prior, current ? &*current : nullptr);
    if (options.dry) {
      output["restored"] = false;
      output["preview"] = true;
      output["removed_edges"] = JsonDoc::array();
    }
  } else
    output = workflow.execute(options.command, options.apply,
                              current ? &*current : nullptr);
  if (options.values.contains("--output"))
    store_document(options.values.at("--output"), output);
  else
    std::cout << output.dump(2) << '\n';
  return output.contains("passed") && !output.at("passed").get<bool>() ? 1 : 0;
}
} // namespace
int main(int argc, char **argv) {
  try {
    return run(argc, argv);
  } catch (const std::exception &error) {
    std::cerr << "arm-flow: " << error.what() << '\n';
    return 2;
  }
}
