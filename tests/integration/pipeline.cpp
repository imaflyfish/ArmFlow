#include <armflow/subprocess.hpp>
#include <armflow/pipeline.hpp>
#include <fstream>
#include <iostream>
using namespace armflow;
namespace {
unsigned passed = 0, failed = 0;
void check(bool value, const std::string &name) {
  if (value)
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
Address named(const BinaryImage &image, const std::string &name) {
  for (const auto &fn : image.functions)
    if (fn.label == name)
      return fn.begin;
  throw FlowError("missing fixture function");
}
std::string scalar(std::uint64_t n) {
  ByteBuffer out(8);
  for (unsigned i = 0; i < 8; ++i)
    out[i] = static_cast<std::uint8_t>(n >> (i * 8));
  return hex_of_bytes(out);
}
} // namespace
int main(int argc, char **argv) {
  if (argc == 3 && std::string(argv[1]) == "--trace-marker") {
    const ByteBuffer input(std::istreambuf_iterator<char>(std::cin), {});
    const auto request = document_of_bytes(input);
    store_document(argv[2], {{"executed", true}});
    std::cout << JsonDoc({{"source_sha256", request.at("source_sha256")},
                       {"observations", {{"sites", JsonDoc::object()}}}}).dump();
    return 0;
  }
  if (argc != 3)
    return 2;
  try {
    auto image = BinaryImage::load(argv[1]);
    JsonDoc ranges = JsonDoc::array();
    for (const auto &region : image.regions)
      if (region.executable)
        ranges.push_back({{"label", region.label}});
    JsonDoc vectors = JsonDoc::array();
    for (const auto &name :
         {"two_constant", "two_choice", "single_choice", "compare_tree"})
      for (unsigned input : {0u, 1u}) {
        const std::string function = name;
        const auto output = function == "two_constant" ? input + 7ULL
                            : function == "two_choice"
                                ? (input == 0 ? 7ULL : std::uint64_t(input) - 3)
                            : function == "single_choice"
                                ? input + (input == 0 ? 11ULL : 19ULL)
                                : input + 2ULL;
        vectors.push_back({{"entry", format_address(named(image, name))},
                           {"input", scalar(input)},
                           {"output", scalar(output)}});
      }
    for (unsigned input : {0u, 1u})
      vectors.push_back({{"entry", format_address(named(image, "bit_selected"))},
                         {"input", input ? "01" : "00"},
                         {"output", scalar(input ? 43 : 41)},
                         {"input_spec", {{"mode", "bytes"}}}});
    JsonDoc config = {{"executable_regions", ranges},
                   {"mode", "linear"},
                   {"analysis", {{"emulate", true}}},
                   {"execution", {{"known_vectors", vectors}}}};
    PipelineDriver workflow(image, config);
    for (const auto &stage : {"survey", "classify", "resolve", "plan"}) {
      auto artifact = workflow.stage(stage);
      check(artifact.at("source_sha256").get<std::string>() ==
                image.fingerprint(),
            "stage binds untouched source snapshot");
      PipelineDriver fresh(image, config);
      fresh.check_artifact(artifact);
      check(true, "serialized stage can be freshly regenerated");
      artifact["source_sha256"] = std::string(64, '0');
      rejects([&] { fresh.check_artifact(artifact); },
              "foreign source rejected");
    }
    auto plan = workflow.stage("plan");
    auto tampered = plan;
    tampered["plan"]["edits"][0]["replacement"] = "1f2003d5";
    rejects([&] { workflow.check_artifact(tampered); },
            "artifact edit tampering rejected");
    auto changed_config = config;
    changed_config["analysis"]["lookback"] = 64;
    rejects(
        [&] { PipelineDriver(image, changed_config).check_artifact(plan); },
        "configuration changes invalidate old stage");
    auto preview = workflow.execute("preview");
    check(!preview.at("applied").get<bool>() &&
              preview.at("added_edges").empty(),
          "preview does not claim graph ownership");
    rejects([&] { workflow.restore(preview); },
            "preview cannot authorize graph deletion");
    auto committed = workflow.execute("run", true);
    check(committed.at("applied").get<bool>() &&
              committed.at("verification").at("passed").get<bool>(),
          "actual candidate passes apply gate");
    check(!committed.at("plan").at("edits").empty(),
          "linear run modifies instructions");
    auto current = BinaryImage::from_snapshot(committed.at("image"));
    auto restored = workflow.restore(committed, &current);
    check(BinaryImage::from_snapshot(restored.at("image")).fingerprint() ==
              image.fingerprint(),
          "workflow restores bytes and exact reference metadata");
    auto again = workflow.execute("run", true);
    check(again == committed,
          "freshly verified apply receipt is deterministic");
    check(workflow.restore(committed, &image).at("restored").get<bool>(),
          "already restored image accepted idempotently");
    current.replace(image.entry, word_bytes(0xd503201f));
    rejects([&] { workflow.restore(committed, &current); },
            "restore refuses unrelated byte drift");
    tampered = committed;
    tampered["added_edges"].push_back({{"source", "0x1"}, {"target", "0x2"}});
    rejects([&] { workflow.restore(tampered); },
            "restore graph log must match regenerated additions");
    auto regression = workflow.execute("regress");
    check(regression.at("passed").get<bool>() &&
              regression.at("identical_plan_and_skips").get<bool>(),
          "regression really restores and reanalyzes");
    check(workflow.execute("verify").at("passed").get<bool>(),
          "verification shares apply gate");
    const auto byte_plan = plan_of_json(plan.at("plan"));
    const auto byte_candidate = PatchTransaction::prepare(image, byte_plan);
    check(workflow.execute("verify", false, &byte_candidate).at("passed"),
          "supplied byte-only candidate passes full verification");
    const auto graph_candidate =
        BinaryImage::from_snapshot(committed.at("image"));
    check(workflow.execute("verify", false, &graph_candidate).at("passed"),
          "supplied applied candidate with owned graph passes verification");
    auto unplanned = byte_candidate;
    unplanned.replace(named(image, "flag_changed"),
                      word_bytes(0xd503201f));
    check(EmulationOracle(config.at("execution"))
                  .compare(image, unplanned)
                  .at("passed") &&
              PatchTransaction::self_check(unplanned, byte_plan).at("passed"),
          "unplanned unexecuted byte change evades output and per-edit checks");
    check(
        !workflow.execute("verify", false, &unplanned).at("passed").get<bool>(),
        "verification rejects bytes changed outside the regenerated plan");
    auto metadata_drift = byte_candidate;
    metadata_drift.regions.front().writable =
        !metadata_drift.regions.front().writable;
    check(!workflow.execute("verify", false, &metadata_drift)
               .at("passed")
               .get<bool>(),
          "verification rejects unplanned memory-permission changes");
    auto foreign_graph = graph_candidate;
    foreign_graph.references.push_back({image.entry, image.entry, true});
    check(!workflow.execute("verify", false, &foreign_graph)
               .at("passed")
               .get<bool>(),
          "verification rejects foreign graph metadata");
    auto partial = config;
    partial["analysis"]["emulate"] = false;
    partial["execution"]["known_vectors"].erase(3);
    PipelineDriver partial_workflow(image, partial);
    const auto partial_plan =
        plan_of_json(partial_workflow.stage("plan").at("plan"));
    const auto partial_candidate =
        PatchTransaction::prepare(image, partial_plan);
    check(EmulationOracle(partial.at("execution"))
              .compare(image, partial_candidate)
              .at("passed"),
          "partial vectors still agree on their observed outputs");
    rejects(
        [&] { partial_workflow.execute("verify"); },
        "implicit verification refuses incomplete dispatch target coverage");
    check(!partial_workflow.execute("verify", false, &partial_candidate)
               .at("passed")
               .get<bool>(),
          "supplied candidate cannot bypass dispatch target coverage");
    auto missing_vector = config;
    missing_vector["analysis"]["emulate"] = false;
    missing_vector["execution"]["known_vectors"].erase(1);
    missing_vector["execution"]["known_vectors"].erase(0);
    PipelineDriver missing_workflow(image, missing_vector);
    const auto missing_plan =
        plan_of_json(missing_workflow.stage("plan").at("plan"));
    const auto missing_candidate =
        PatchTransaction::prepare(image, missing_plan);
    check(!missing_workflow.execute("verify", false, &missing_candidate)
               .at("passed")
               .get<bool>(),
          "supplied candidate cannot bypass edited-instruction coverage");
    auto trace = workflow.execute("trace");
    check(trace.at("executions").size() == vectors.size(),
          "trace drives every known vector");
    check(!trace.at("observations").at("sites").empty(),
          "trace collects actual BR destinations");
    check(workflow.execute("discover").at("jobs").size() == 7,
          "discovery groups all seven functions");
    auto scoped = config;
    scoped["functions"] = JsonDoc::array({"two_constant"});
    auto scoped_plan = PipelineDriver(image, scoped).stage("plan");
    check(scoped_plan.at("sites").size() == 1 &&
              scoped_plan.at("plan").at("edits").size() == 1,
          "function selection constrains edits");
    auto missing = config;
    missing.erase("execution");
    missing["analysis"]["emulate"] = false;
    rejects([&] { PipelineDriver(image, missing).execute("run", true); },
            "missing execution contract blocks byte application");
    auto graph_config = missing;
    graph_config["mode"] = "graph";
    auto existing = image;
    auto proposed = plan_of_json(plan.at("plan"));
    existing.references.push_back(proposed.graph.front());
    PipelineDriver graph_workflow(existing, graph_config);
    auto graph = graph_workflow.execute("graph", true);
    check(graph.at("plan").at("edits").empty(),
          "graph mode changes metadata only");
    check(graph.at("added_edges").size() + 1 == proposed.graph.size(),
          "pre-existing graph edge is excluded from ownership log");
    check(BinaryImage::from_snapshot(graph_workflow.restore(graph).at("image"))
                  .fingerprint() == existing.fingerprint(),
          "graph restore preserves pre-existing edge");
    auto wrong = config;
    wrong["execution"]["known_vectors"][0]["output"] = scalar(999);
    rejects([&] { PipelineDriver(image, wrong).execute("trace"); },
            "failed original vector cannot become trace evidence");
    rejects([&] { workflow.execute("survey", true); },
            "read-only command rejects apply");
    // Exercise the actual CLI, including atomic outputs and relative config
    // paths.
    ScratchDirectory temp;
    store_document(temp.path() / "source.json", image.snapshot());
    auto cli_config = config;
    cli_config["image"] = "source.json";
    store_document(temp.path() / "job.json", cli_config);
    const auto source_bytes = load_file(temp.path() / "source.json");
    auto invoke = [&](std::vector<std::string> extra) {
      std::vector<std::string> args{argv[2]};
      args.insert(args.end(), extra.begin(), extra.end());
      return spawn_process(args, {}, 60000);
    };
    auto output = temp.path() / "result.json";
    for (const auto &command :
         {"survey", "classify", "resolve", "plan", "preview", "trace",
          "discover", "verify", "regress"}) {
      const auto result =
          invoke({command, "--config", (temp.path() / "job.json").string(),
                  "--output", output.string()});
      check(result.exit_code == 0,
            "CLI command completes: " + std::string(command));
      if (result.exit_code != 0)
        std::cerr << std::string(result.errors.begin(), result.errors.end());
    }
    auto applied = temp.path() / "applied.json";
    check(invoke({"run", "--config", (temp.path() / "job.json").string(),
                  "--apply", "--output", applied.string()})
                  .exit_code == 0,
          "CLI applies through verified transaction");
    check(invoke({"restore", "--config", (temp.path() / "job.json").string(),
                  "--from", applied.string(), "--output", output.string()})
                  .exit_code == 0,
          "CLI restores matching receipt");
    check(load_file(temp.path() / "source.json") == source_bytes,
          "CLI preserves original source bytes");
    check(invoke({"run", "--config", (temp.path() / "job.json").string(),
                  "--output", (temp.path() / "source.json").string()})
                  .exit_code == 2,
          "CLI refuses overwrite of input image");
    check(invoke({"plan", "--config", (temp.path() / "job.json").string(),
                  "--output", (temp.path() / "job.json").string()})
                  .exit_code == 2,
          "CLI refuses overwrite of configuration");
    check(invoke({"snapshot", (temp.path() / "source.json").string(),
                  (temp.path() / "source.json").string()})
                  .exit_code == 2,
          "snapshot refuses source replacement");
    check(invoke({"run", "--config", (temp.path() / "job.json").string(),
                  "--apply", "--dry-run"})
                  .exit_code == 2,
          "CLI rejects contradictory flags");
    check(invoke({"plan", "--config", (temp.path() / "job.json").string(),
                  "--config", (temp.path() / "job.json").string()})
                  .exit_code == 2,
          "CLI rejects duplicate options");
    const auto marker = temp.path() / "trace-marker.json";
    const auto traced_config_path = temp.path() / "traced-job.json";
    const auto inline_trace = temp.path() / "empty-trace.json";
    const auto malformed = temp.path() / "malformed.json";
    store_document(inline_trace, {{"sites", JsonDoc::object()}});
    {
      std::ofstream bad_document(malformed);
      bad_document << "{not JSON";
    }
    auto traced_config = cli_config;
    traced_config["trace_files"] = JsonDoc::array({inline_trace.string()});
    traced_config["trace_command"] = {
        {"argv", JsonDoc::array({argv[0], "--trace-marker", marker.string()})}};
    store_document(traced_config_path, traced_config);
    const std::vector<std::pair<std::string, std::vector<std::string>>> invalid_requests{
        {"unknown command", {"not-a-command"}},
        {"unsupported current", {"plan", "--current", (temp.path() / "source.json").string()}},
        {"read-only apply", {"plan", "--apply"}},
        {"missing restore receipt", {"restore"}},
        {"restore apply", {"restore", "--apply", "--from", applied.string()}},
        {"source output", {"plan", "--output", (temp.path() / "source.json").string()}},
        {"config output", {"plan", "--output", traced_config_path.string()}},
        {"trace output", {"plan", "--output", inline_trace.string()}},
        {"artifact output", {"plan", "--from", applied.string(), "--output", applied.string()}},
        {"current output", {"verify", "--current", applied.string(), "--output", applied.string()}},
        {"malformed artifact", {"plan", "--from", malformed.string()}},
        {"malformed current", {"verify", "--current", malformed.string()}}};
    for (const auto &[name, supplied] : invalid_requests) {
      std::filesystem::remove(marker);
      auto request = supplied;
      request.insert(request.end(), {"--config", traced_config_path.string()});
      const auto result = invoke(request);
      check(result.exit_code == 2 && !std::filesystem::exists(marker),
            "CLI rejects " + name + " before launching a configured trace");
    }
    std::filesystem::remove(marker);
    check(invoke({"plan", "--config", traced_config_path.string(),
                  "--output", output.string()}).exit_code == 0 &&
              std::filesystem::exists(marker),
          "valid CLI request still launches its configured trace");
    const auto before = load_file(output);
    store_document(temp.path() / "bad.json", {{"image", "source.json"},
                                              {"mode", "linear"},
                                              {"executable_regions", ranges}});
    check(invoke({"run", "--config", (temp.path() / "bad.json").string(),
                  "--apply", "--output", output.string()})
                  .exit_code == 2,
          "CLI missing verifier fails");
    check(load_file(output) == before,
          "failed run preserves previous output artifact");
    // A changed candidate must fail the public verify command, not just a unit
    // oracle.
    auto corrupted = image;
    corrupted.replace(named(image, "two_constant") + 36,
                      word_bytes(0x91002000));
    store_document(temp.path() / "wrong.json", corrupted.snapshot());
    auto verify_result = invoke(
        {"verify", "--config", (temp.path() / "job.json").string(), "--current",
         (temp.path() / "wrong.json").string(), "--output", output.string()});
    check(verify_result.exit_code == 1,
          "wrong candidate yields CLI verification failure");
    store_document(temp.path() / "unplanned.json", unplanned.snapshot());
    check(invoke({"verify", "--config", (temp.path() / "job.json").string(),
                  "--current", (temp.path() / "unplanned.json").string(),
                  "--output", output.string()})
                  .exit_code == 1,
          "CLI rejects unplanned bytes even when supplied vectors pass");
    auto partial_cli = partial;
    partial_cli["image"] = "source.json";
    store_document(temp.path() / "partial.json", partial_cli);
    store_document(temp.path() / "partial-candidate.json",
                   partial_candidate.snapshot());
    check(
        invoke({"verify", "--config", (temp.path() / "partial.json").string(),
                "--current", (temp.path() / "partial-candidate.json").string(),
                "--output", output.string()})
                .exit_code == 1,
        "CLI supplied-candidate verification enforces target coverage");
    auto fractional = config;
    fractional["analysis"]["lookback"] = 1.5;
    rejects([&] { PipelineDriver invalid(image, fractional); },
            "fractional analysis budget rejected");
    fractional["analysis"]["lookback"] = std::uint64_t{1} << 40;
    rejects([&] { PipelineDriver invalid(image, fractional); },
            "analysis budget does not wrap at 32 bits");
    auto limited = config;
    limited["analysis"]["maximum_targets"] = 1;
    rejects([&] { PipelineDriver(image, limited).stage("plan"); },
            "configured target budget is enforced");
    auto foreign_trace = trace;
    foreign_trace["source_sha256"] = std::string(64, '0');
    store_document(temp.path() / "foreign-trace.json", foreign_trace);
    auto tracing = cli_config;
    tracing["trace_files"] = JsonDoc::array({"foreign-trace.json"});
    store_document(temp.path() / "tracing.json", tracing);
    check(
        invoke({"resolve", "--config", (temp.path() / "tracing.json").string()})
                .exit_code == 2,
        "CLI rejects a trace artifact bound to another source");
    auto filtered = config;
    filtered["analysis"]["state_bases"] = JsonDoc::array({29});
    const auto no_sp = PipelineDriver(image, filtered).stage("survey");
    bool has_stack_slot = false;
    for (const auto &site : no_sp.at("sites"))
      has_stack_slot = has_stack_slot || !site.at("state_slot").is_null();
    check(!has_stack_slot,
          "state base filter excludes SP slots in neutral fixture");
    filtered = config;
    filtered["analysis"]["index_registers"] = JsonDoc::array({30});
    filtered["analysis"]["comparison_tree"] = false;
    check(PipelineDriver(image, filtered).stage("survey").at("sites").empty(),
          "index register allowlist filters both table models");
    filtered["analysis"]["index_registers"] = JsonDoc::array({32});
    rejects([&] { PipelineDriver invalid(image, filtered); },
            "out-of-range register filter refused");
    auto expected_config = config;
    expected_config["regression"] = {
        {"minimum_edits", preview.at("plan").at("edits").size()},
        {"maximum_skips", preview.at("plan").at("skipped").size()},
        {"expected_skips", preview.at("plan").at("skipped")}};
    const auto sample_edit = preview.at("plan").at("edits")[0];
    expected_config["regression"]["instruction_samples"] = JsonDoc::array(
        {{{"address", sample_edit.at("address")},
          {"target", sample_edit.at("target")},
          {"word", format_address(*BinaryImage::from_snapshot(preview.at("image"))
                                    .instruction(address_of_json(
                                        sample_edit.at("address"))))}}});
    check(PipelineDriver(image, expected_config)
              .execute("regress")
              .at("passed")
              .get<bool>(),
          "independent baseline counts, skip set and instruction expectations "
          "pass");
    auto bad_expectation = expected_config;
    bad_expectation["regression"]["minimum_edits"] = 1000;
    check(!PipelineDriver(image, bad_expectation)
               .execute("regress")
               .at("passed")
               .get<bool>(),
          "regression reports a missed edit baseline");
    rejects(
        [&] { PipelineDriver(image, bad_expectation).execute("run", true); },
        "apply cannot ignore failed baseline expectations");
    bad_expectation = expected_config;
    bad_expectation["regression"]["instruction_samples"][0]["target"] =
        "0x1000";
    check(!PipelineDriver(image, bad_expectation)
               .execute("verify")
               .at("passed")
               .get<bool>(),
          "wrong expected branch target fails verification");
    bad_expectation = expected_config;
    bad_expectation["regression"]["expected_skips"] = JsonDoc::array();
    rejects(
        [&] { PipelineDriver(image, bad_expectation).execute("run", true); },
        "unexpected skipped site prevents configured application");
    auto batch_config = config;
    batch_config["jobs"] = JsonDoc::array(
        {{{"name", "bad"}, {"functions", JsonDoc::array({"absent_function"})}},
         {{"name", "good"}, {"functions", JsonDoc::array({"two_choice"})}}});
    auto batch = PipelineDriver(image, batch_config).execute("batch", true);
    check(!batch.at("passed").get<bool>() &&
              !batch.at("groups")[0].at("passed").get<bool>() &&
              batch.at("groups")[1].at("passed").get<bool>(),
          "failed batch group does not prevent later verified group");
    const auto &good = batch.at("groups")[1];
    check(good.at("result").at("applied").get<bool>() &&
              good.at("result").at("verification").at("passed").get<bool>(),
          "batch application still uses the byte behavior gate");
    check(PipelineDriver(image, good.at("configuration"))
              .restore(good.at("result"))
              .at("restored")
              .get<bool>(),
          "each batch receipt restores with its recorded scoped configuration");
    auto automatic = PipelineDriver(image, config).execute("batch");
    check(automatic.at("passed").get<bool>() &&
              automatic.at("group_count") == 6,
          "automatic grouping produces six groups for seven functions sharing "
          "one table");
    bool shared_group = false;
    for (const auto &group : automatic.at("groups"))
      shared_group =
          shared_group || group.at("configuration").at("functions").size() == 2;
    check(shared_group,
          "functions using the same dispatch table share one batch group");
    auto command_config = config;
    command_config["analysis"]["emulate"] = false;
    command_config["trace_command"] = {
        {"argv",
         JsonDoc::array({argv[2], "trace", "--image", "{image}", "--config",
                      (temp.path() / "job.json").string()})}};
    auto traced_workflow = PipelineDriver(image, command_config);
    check(traced_workflow.stage("resolve").at("observations") ==
              trace.at("observations"),
          "external native trace command supplies source-bound observations");
    check(!traced_workflow.configuration().contains("trace_command") &&
              traced_workflow.configuration().contains("observations"),
          "trace result is materialized into reproducible configuration");
    command_config["trace_command"]["argv"] = JsonDoc::array(
        {"/bin/cat", (temp.path() / "foreign-trace.json").string()});
    rejects([&] { PipelineDriver invalid(image, command_config); },
            "foreign command trace cannot enter evidence");
    command_config["trace_command"]["timeout_milliseconds"] = 0;
    rejects([&] { PipelineDriver invalid(image, command_config); },
            "zero trace command timeout is rejected");
    auto batch_cli = cli_config;
    batch_cli["jobs"] = batch_config.at("jobs");
    store_document(temp.path() / "batch.json", batch_cli);
    check(
        invoke({"batch", "--config", (temp.path() / "batch.json").string(),
                "--apply", "--output", output.string()})
                .exit_code == 1,
        "CLI batch returns failure while retaining successful group artifact");
    check(load_document(output)
              .at("groups")[1]
              .at("result")
              .at("applied")
              .get<bool>(),
          "successful batch receipt survives a preceding group failure");
    std::cout << passed << " workflow checks passed; " << failed << " failed\n";
    return failed ? 1 : 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
