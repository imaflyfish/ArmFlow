#include <algorithm>
#include <armflow/pipeline.hpp>
#include <set>
namespace armflow {
namespace {
std::string document_hash(const JsonDoc &document) {
  // Object ordering in configuration files is not significant.
  const auto encoded = nlohmann::json(document).dump();
  return sha256_hex(
      {reinterpret_cast<const std::uint8_t *>(encoded.data()), encoded.size()});
}
unsigned stage_depth(const std::string &stage) {
  if (stage == "survey")
    return 1;
  if (stage == "classify")
    return 2;
  if (stage == "resolve")
    return 3;
  if (stage == "plan")
    return 4;
  throw FlowError("unknown analysis stage: " + stage);
}
void validate_observations(const BinaryImage &image,
                           const SurveyObservations &observations,
                           unsigned maximum_targets) {
  for (const auto &[site, targets] : observations.targets) {
    if (targets.size() > maximum_targets)
      throw FlowError("observed target count exceeds maximum_targets");
    auto instruction = image.instruction(site);
    if (!instruction || (*instruction & 0xfffffc1f) != 0xd61f0000)
      throw FlowError("trace site is not a mapped BR instruction");
    for (auto target : targets)
      if (!image.valid_target(target))
        throw FlowError("trace target is not aligned executable memory");
  }
}
} // namespace
PipelineDriver::PipelineDriver(BinaryImage input, JsonDoc configuration)
    : input_(std::move(input)), analysis_image_(input_),
      configuration_(std::move(configuration)),
      settings_(FlowSettings::from_json(configuration_, input_)) {
  input_.validate();
  mode_ = configuration_.value("mode", std::string("graph"));
  if (mode_ != "graph" && mode_ != "linear" && mode_ != "full")
    throw FlowError("mode must be graph, linear or full");
  gather_direct_edges(analysis_image_, decoder_);
  if (configuration_.contains("functions")) {
    const auto &selectors = configuration_.at("functions");
    if (!selectors.is_array() || selectors.empty() || selectors.size() > 10000)
      throw FlowError(
          "functions must select 1..10000 function entries or names");
    std::vector<std::pair<Address, Address>> ranges;
    for (const auto &selector : selectors) {
      const RoutineSpan *function = nullptr;
      for (const auto &entry : input_.functions)
        if (selector.is_string() &&
            entry.label == selector.get<std::string>()) {
          if (function)
            throw FlowError("ambiguous function name");
          function = &entry;
        }
      if (!function) {
        auto address = address_of_json(selector);
        function = input_.function_at(address);
        if (!function || function->begin != address)
          throw FlowError("function selector must identify a function entry");
      }
      bool selected = false;
      for (const auto &[begin, end] : settings_.ranges) {
        const auto first = std::max(begin, function->begin),
                   last = std::min(end, function->end);
        if (first < last) {
          ranges.emplace_back(first, last);
          selected = true;
        }
      }
      if (!selected)
        throw FlowError("function lies outside selected executable regions");
    }
    settings_.ranges = std::move(ranges);
  }
  if (configuration_.contains("trace_command")) {
    observations_.merge(
        gather_external_trace(input_, configuration_.at("trace_command")));
    if (configuration_.contains("observations"))
      observations_.merge(configuration_.at("observations"));
    configuration_["observations"] = observations_.json();
    configuration_.erase("trace_command");
  }
  configuration_hash_ = document_hash(configuration_);
  if (configuration_.contains("observations")) {
    observations_.merge(configuration_.at("observations"));
    validate_observations(input_, observations_, settings_.maximum_targets);
  }
}
JsonDoc PipelineDriver::envelope(const std::string &name) const {
  return {{"schema_version", 1},
          {"producer", "ArmFlow"},
          {"stage", name},
          {"source_sha256", input_.fingerprint()},
          {"configuration_sha256", configuration_hash_}};
}
JsonDoc PipelineDriver::exercise() {
  if (exercised_)
    return executions_;
  const auto specification = configuration_.at("execution");
  const auto vectors = specification.value("known_vectors", JsonDoc::array());
  if (!vectors.is_array() || vectors.empty() || vectors.size() > 10000)
    throw FlowError("trace and emulation require 1..10000 known vectors");
  // Stage all observations locally. A failed vector must not leave a partially
  // trusted trace behind when this workflow object is reused by an embedding.
  auto accumulated = observations_;
  auto states = state_targets_;
  JsonDoc rows = JsonDoc::array();
  for (const auto &vector : vectors) {
    auto local = specification;
    if (vector.contains("input_spec"))
      local["input"] = vector["input_spec"];
    if (vector.contains("output_spec"))
      local["output"] = vector["output_spec"];
    auto entry =
        address_of_json(vector.contains("entry") ? vector.at("entry")
                                                 : specification.at("entry"));
    auto input = bytes_of_hex(vector.at("input"));
    auto expected = bytes_of_hex(vector.at("output"));
    auto result = EmulationOracle(local).run(input_, entry, input, sites_);
    if (result.output != expected)
      throw FlowError("known vector does not match the original image at " +
                      format_address(entry));
    accumulated.merge(result.observations.json());
    validate_observations(input_, accumulated, settings_.maximum_targets);
    for (const auto &[site, values] : result.state_targets)
      for (const auto &[state, targets] : values)
        states[site][state].insert(targets.begin(), targets.end());
    rows.push_back({{"entry", format_address(entry)},
                    {"input", hex_of_bytes(input)},
                    {"expected", hex_of_bytes(expected)},
                    {"execution", json_of_execution(result)}});
  }
  observations_ = std::move(accumulated);
  state_targets_ = std::move(states);
  executions_ = std::move(rows);
  exercised_ = true;
  return executions_;
}
void PipelineDriver::analyze(unsigned depth) {
  if (depth_ < 1 && depth >= 1) {
    sites_ = survey_switches(analysis_image_, decoder_, settings_);
    // A range may cover part of a function. Every proposed byte still has to
    // lie in that range; filtering solely by the function's entry is unsafe.
    depth_ = 1;
  }
  if (depth_ < 2 && depth >= 2) {
    transitions_ =
        classify_transitions(analysis_image_, decoder_, settings_, sites_);
    depth_ = 2;
  }
  if (depth_ < 3 && depth >= 3) {
    if (configuration_.value("analysis", JsonDoc::object())
            .value("emulate", false))
      exercise();
    flows_ = resolve_targets(analysis_image_, settings_, sites_, transitions_,
                             observations_);
    for (auto &flow : flows_) {
      auto at_site = state_targets_.find(flow.transition.branch);
      if (at_site == state_targets_.end())
        continue;
      for (auto &target : flow.targets) {
        auto found = at_site->second.find(target.state);
        if (found == at_site->second.end() || found->second.empty())
          continue;
        if (found->second.size() != 1 ||
            (target.destination &&
             !found->second.contains(*target.destination))) {
          target.evidence = "conflict";
          target.reason = "execution disagrees with the state-specific static "
                          "target or observed multiple targets";
          continue;
        }
        const auto destination = *found->second.begin();
        if (!input_.valid_target(destination)) {
          target.evidence = "invalid";
          target.reason = "emulated target is not aligned executable memory";
        } else if (!target.destination) {
          target.destination = destination;
          target.evidence = "emulated";
          target.reason =
              "state-specific execution evidence; not a proof over all inputs";
        }
      }
    }
    expansion_ = expand_states(analysis_image_, decoder_, settings_, sites_,
                               flows_, observations_, state_targets_);
    depth_ = 3;
  }
  if (depth_ < 4 && depth >= 4) {
    plan_ = plan_patches(analysis_image_, decoder_, settings_, sites_, flows_,
                         observations_);
    plan_.source_sha256 = input_.fingerprint();
    std::set<std::pair<Address, Address>> graph;
    for (const auto &edge : plan_.graph)
      graph.emplace(edge.source, edge.target);
    for (const auto &site : sites_) {
      const auto found = observations_.targets.find(site.branch);
      if (found != observations_.targets.end())
        for (auto target : found->second)
          if (graph.emplace(site.branch, target).second)
            plan_.graph.push_back({site.branch, target, false});
    }
    std::set<Address> rejected;
    for (const auto &edit : plan_.edits)
      if (!settings_.selects(edit.address))
        rejected.insert(edit.site);
    std::erase_if(plan_.edits, [&](const auto &edit) {
      return rejected.contains(edit.site);
    });
    for (auto site : rejected)
      plan_.skipped.push_back(
          {{"site", format_address(site)},
           {"reason",
            "one or more grouped edits lie outside the selected ranges"}});
    table_graph_ =
        extend_table_graph(analysis_image_, settings_, sites_, plan_);
    depth_ = 4;
  }
}
JsonDoc PipelineDriver::stage(const std::string &name) {
  const auto depth = stage_depth(name);
  analyze(depth);
  auto result = envelope(name);
  result["sites"] = JsonDoc::array();
  for (const auto &site : sites_)
    result["sites"].push_back(json_of_site(site));
  if (depth >= 2) {
    result["transitions"] = JsonDoc::array();
    for (const auto &transition : transitions_)
      result["transitions"].push_back(json_of_transition(transition));
  }
  if (depth >= 3) {
    result["flows"] = JsonDoc::array();
    for (const auto &flow : flows_)
      result["flows"].push_back(json_of_branch(flow));
    result["observations"] = observations_.json();
    result["executions"] = executions_;
    result["state_expansion"] = expansion_;
  }
  if (depth >= 4) {
    result["plan"] = plan_.json();
    result["table_graph"] = table_graph_;
  }
  return result;
}
void PipelineDriver::check_artifact(const JsonDoc &artifact) {
  if (artifact.at("schema_version") != 1 ||
      artifact.at("producer") != "ArmFlow" ||
      artifact.at("source_sha256").get<std::string>() != input_.fingerprint() ||
      artifact.at("configuration_sha256").get<std::string>() !=
          configuration_hash_)
    throw FlowError("artifact version, source or configuration does not match");
  const auto name = artifact.at("stage").get<std::string>();
  auto expected = stage(name);
  if (nlohmann::json(expected) != nlohmann::json(artifact))
    throw FlowError("stage artifact differs from freshly regenerated analysis");
}
PatchPlan PipelineDriver::effective_plan(const std::string &command) const {
  if (command == "cleanup") {
    auto proposal = plan_filler_cleanup(analysis_image_, decoder_, settings_);
    proposal.source_sha256 = input_.fingerprint();
    return proposal;
  }
  auto result = plan_;
  if (command == "graph" || mode_ == "graph")
    result.edits.clear();
  return result;
}
BinaryImage PipelineDriver::with_graph(BinaryImage candidate,
                                       const PatchPlan &plan,
                                       JsonDoc &added) const {
  std::set<std::pair<Address, Address>> known;
  for (const auto &edge : candidate.references)
    known.emplace(edge.source, edge.target);
  added = JsonDoc::array();
  for (const auto &edge : plan.graph)
    if (known.emplace(edge.source, edge.target).second) {
      candidate.references.push_back({edge.source, edge.target, true});
      added.push_back({{"source", format_address(edge.source)},
                       {"target", format_address(edge.target)}});
    }
  return candidate;
}
JsonDoc PipelineDriver::receipt(const std::string &command,
                                const PatchPlan &plan,
                                const BinaryImage &candidate,
                                const JsonDoc &added, bool applied,
                                const JsonDoc &verification) const {
  auto result = envelope(command);
  result["mode"] = mode_;
  result["applied"] = applied;
  result["plan"] = plan.json();
  result["verification"] = verification;
  result["table_graph"] = table_graph_;
  result["state_expansion"] = expansion_;
  result["candidate_sha256"] = candidate.fingerprint();
  result["added_edges"] = applied ? added : JsonDoc::array();
  result["proposed_edges"] = added;
  result["image"] = candidate.snapshot();
  return result;
}
JsonDoc PipelineDriver::execute(const std::string &command, bool apply,
                                const BinaryImage *candidate) {
  if (command == "batch")
    return execute_batch(apply);
  if (command == "survey" || command == "classify" || command == "resolve" ||
      command == "plan") {
    if (apply)
      throw FlowError("analysis stages are read-only");
    return stage(command);
  }
  if (command == "trace") {
    if (apply)
      throw FlowError("trace is read-only");
    analyze(1);
    auto result = envelope("trace");
    result["executions"] = exercise();
    result["observations"] = observations_.json();
    // Trace may have changed evidence after a caller requested another stage.
    depth_ = std::min(depth_, 2u);
    return result;
  }
  if (command == "discover") {
    if (apply)
      throw FlowError("discover is read-only");
    analyze(4);
    auto result = envelope(command);
    result["jobs"] = JsonDoc::array();
    for (const auto &function : input_.functions) {
      JsonDoc sites = JsonDoc::array();
      for (const auto &site : sites_)
        if (site.parent == function.begin)
          sites.push_back(format_address(site.branch));
      if (sites.empty())
        continue;
      std::size_t edits = 0, skipped = 0;
      for (const auto &edit : plan_.edits)
        edits += edit.parent == function.begin;
      for (const auto &skip : plan_.skipped)
        if (skip.contains("site")) {
          auto parent = input_.function_at(address_of_json(skip.at("site")));
          skipped += parent && parent->begin == function.begin;
        }
      result["jobs"].push_back({{"function", format_address(function.begin)},
                                {"name", function.label},
                                {"sites", sites},
                                {"proposed_instructions", edits},
                                {"skipped", skipped}});
    }
    return result;
  }
  if (command != "preview" && command != "run" && command != "graph" &&
      command != "verify" && command != "regress" && command != "cleanup")
    throw FlowError("unknown workflow command: " + command);
  if (apply && command != "run" && command != "graph" && command != "cleanup")
    throw FlowError("--apply is only valid for run, graph and cleanup");
  if (apply && command == "cleanup" && mode_ == "graph")
    throw FlowError("cleanup application requires mode linear or full");
  analyze(4);
  auto plan = effective_plan(command);
  auto prepared = PatchTransaction::prepare(input_, plan);
  auto expectations = verify_plan_expectations(
      prepared, plan, configuration_.value("regression", JsonDoc::object()));
  if (apply && !expectations.at("passed").get<bool>())
    throw FlowError(
        "configured regression expectations failed; application refused");
  JsonDoc verification = {{"status", "not_run"}, {"passed", false}};
  if (command == "verify" || command == "regress" ||
      (apply && !plan.edits.empty())) {
    EmulationOracle oracle(configuration_.at("execution"));
    if (command == "verify" && candidate) {
      // A supplied snapshot must be the regenerated byte candidate, optionally
      // with exactly the graph metadata that this workflow owns. Per-edit
      // checks and finite outputs cannot identify changes elsewhere in an
      // image.
      JsonDoc added;
      const auto graphed = with_graph(prepared, plan, added);
      const auto supplied_hash = candidate->fingerprint();
      const bool matches = supplied_hash == prepared.fingerprint() ||
                           supplied_hash == graphed.fingerprint();
      if (!matches) {
        verification = {{"status", "not_run"},
                        {"passed", false},
                        {"error", "supplied candidate differs from the "
                                  "regenerated bytes or owned graph"}};
      } else {
        // Reuse every application gate, including original instruction/target
        // coverage and all candidate branch outcomes. The matching fingerprints
        // above bind the supplied bytes to the image exercised by this gate.
        auto checked = input_;
        try {
          verification =
              PatchTransaction::commit(checked, input_, plan, oracle);
          verification["status"] = "passed";
        } catch (const FlowError &error) {
          verification = {
              {"status", "failed"}, {"passed", false}, {"error", error.what()}};
        }
      }
      auto result = envelope(command);
      result["candidate_match"] = matches;
      result["supplied_sha256"] = supplied_hash;
      result["verification"] = verification;
      result["self_check"] = PatchTransaction::self_check(*candidate, plan);
      result["expectations"] = verify_plan_expectations(
          *candidate, plan,
          configuration_.value("regression", JsonDoc::object()));
      result["passed"] = result.at("expectations").at("passed").get<bool>() &&
                         verification.at("passed").get<bool>() &&
                         result["self_check"].at("passed").get<bool>();
      return result;
    }
    // The same coverage and target-set requirements guard CLI and library
    // writes.
    auto current = input_;
    verification = PatchTransaction::commit(current, input_, plan, oracle);
    verification["status"] = "passed";
    prepared = std::move(current);
  }
  if (command == "regress") {
    auto restored = prepared;
    PatchTransaction::restore(restored, input_, plan);
    PipelineDriver rerun(restored, configuration_);
    const auto repeated = rerun.stage("plan");
    const bool same_plan =
        nlohmann::json(repeated.at("plan")) == nlohmann::json(plan_.json());
    auto restored_vectors = EmulationOracle(configuration_.at("execution"))
                                .compare(input_, restored, sites_);
    auto result = envelope(command);
    result["verification"] = verification;
    result["restored_verification"] = restored_vectors;
    result["restored_sha256"] = restored.fingerprint();
    result["identical_plan_and_skips"] = same_plan;
    result["expectations"] = expectations;
    result["passed"] = expectations.at("passed").get<bool>() && same_plan &&
                       restored.fingerprint() == input_.fingerprint() &&
                       restored_vectors.at("passed").get<bool>();
    return result;
  }
  JsonDoc added;
  auto prospective = with_graph(std::move(prepared), plan, added);
  auto result = receipt(command, plan, prospective, added, apply, verification);
  result["expectations"] = expectations;
  if (command == "verify")
    result["passed"] = verification.at("passed").get<bool>() &&
                       expectations.at("passed").get<bool>();
  return result;
}
JsonDoc PipelineDriver::restore(const JsonDoc &record,
                                const BinaryImage *current) {
  if (record.at("schema_version") != 1 || record.at("producer") != "ArmFlow" ||
      !record.at("applied").get<bool>() ||
      record.at("source_sha256").get<std::string>() != input_.fingerprint() ||
      record.at("configuration_sha256").get<std::string>() !=
          configuration_hash_)
    throw FlowError("restore requires a matching applied receipt");
  const auto command = record.at("stage").get<std::string>();
  if (command != "run" && command != "graph" && command != "cleanup")
    throw FlowError("receipt is not from an applying command");
  analyze(4);
  auto plan = effective_plan(command);
  if (nlohmann::json(record.at("plan")) != nlohmann::json(plan.json()))
    throw FlowError("receipt plan differs from current source analysis");
  JsonDoc added;
  auto expected =
      with_graph(PatchTransaction::prepare(input_, plan), plan, added);
  const auto recorded = BinaryImage::from_snapshot(record.at("image"));
  if (record.at("candidate_sha256").get<std::string>() !=
          expected.fingerprint() ||
      recorded.fingerprint() != expected.fingerprint() ||
      record.at("added_edges") != added)
    throw FlowError("receipt image or graph ownership does not match");
  if (current && current->fingerprint() != expected.fingerprint() &&
      current->fingerprint() != input_.fingerprint())
    throw FlowError("current image has unrelated changes; restore refused");
  auto result = envelope("restore");
  result["restored"] = true;
  result["removed_edges"] = added;
  result["image"] = input_.snapshot();
  result["restored_sha256"] = input_.fingerprint();
  return result;
}
} // namespace armflow
