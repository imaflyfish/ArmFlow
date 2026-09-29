#include <algorithm>
#include <armflow/emulation.hpp>
#include <armflow/subprocess.hpp>
#include <cctype>
namespace armflow {
namespace {
void substitute(std::string &argument, const std::string &key,
                const std::string &value) {
  std::size_t start = 0;
  while ((start = argument.find(key, start)) != std::string::npos) {
    argument.replace(start, key.size(), value);
    start += value.size();
  }
}
} // namespace
JsonDoc json_of_execution(const EmulationResult &result) {
  JsonDoc coverage = JsonDoc::array(), states = JsonDoc::object(),
          edges = JsonDoc::object();
  for (auto address : result.executed)
    coverage.push_back(format_address(address));
  for (const auto &[source, destinations] : result.control_edges) {
    auto &values = edges[format_address(source)] = JsonDoc::array();
    for (auto target : destinations)
      values.push_back(format_address(target));
  }
  for (const auto &[site, values] : result.state_targets) {
    auto &entries = states[format_address(site)] = JsonDoc::object();
    for (const auto &[state, targets] : values) {
      auto &destinations = entries[format_address(state)] = JsonDoc::array();
      for (auto target : targets)
        destinations.push_back(format_address(target));
    }
  }
  return {{"output", hex_of_bytes(result.output)},
          {"returned", format_address(result.returned)},
          {"instructions", result.instructions},
          {"observations", result.observations.json()},
          {"coverage", coverage},
          {"control_edges", edges},
          {"state_targets", states}};
}
EmulationResult execution_of_json(const JsonDoc &record,
                                  const BinaryImage &image) {
  EmulationResult result;
  result.output = bytes_of_hex(record.at("output"));
  if (result.output.size() > 1024 * 1024)
    throw FlowError("oracle response output limit exceeded");
  result.returned = address_of_json(record.at("returned"));
  result.instructions = address_of_json(record.at("instructions"));
  if (result.instructions == 0 ||
      result.instructions > maximum_executed_instructions)
    throw FlowError("oracle response has invalid instruction count");
  result.observations.merge(record.at("observations"));
  const auto &coverage = record.at("coverage");
  if (!coverage.is_array() || coverage.empty() || coverage.size() > 1000000)
    throw FlowError("oracle response requires bounded instruction coverage");
  for (const auto &address : coverage) {
    auto point = address_of_json(address);
    if (!image.instruction(point))
      throw FlowError("oracle coverage contains an unmapped instruction");
    result.executed.insert(point);
  }
  const auto edges = record.value("control_edges", JsonDoc::object());
  if (!edges.is_object() || edges.size() > 1000000)
    throw FlowError("invalid executed control-edge table");
  std::size_t edge_count = 0;
  for (const auto &[source, destinations] : edges.items()) {
    auto address = address_of_json(JsonDoc(source));
    if (!image.instruction(address) || !destinations.is_array() ||
        destinations.size() > maximum_document_entries)
      throw FlowError("invalid executed control edge");
    for (const auto &target : destinations) {
      if (++edge_count > 2000000)
        throw FlowError("executed edge count limit exceeded");
      const auto destination = address_of_json(target);
      if (destination % 4)
        throw FlowError("executed edge target is not aligned");
      result.control_edges[address].insert(destination);
    }
  }
  const auto &states = record.value("state_targets", JsonDoc::object());
  if (!states.is_object() || states.size() > maximum_document_entries)
    throw FlowError("invalid observed-state table");
  std::size_t values = 0;
  for (const auto &[site, entries] : states.items()) {
    auto branch = address_of_json(JsonDoc(site));
    if (!image.instruction(branch) || !entries.is_object())
      throw FlowError("invalid observed-state site");
    for (const auto &[state, targets] : entries.items()) {
      if (++values > 1000000 || !targets.is_array() ||
          targets.size() > maximum_document_entries)
        throw FlowError("observed-state count limit exceeded");
      for (const auto &target : targets)
        result.state_targets[branch][address_of_json(JsonDoc(state))].insert(
            address_of_json(target));
    }
  }
  return result;
}
EmulationResult command_execution(const JsonDoc &specification,
                                  const BinaryImage &image, Address entry,
                                  std::span<const std::uint8_t> input,
                                  const std::vector<SwitchSite> &sites) {
  ScratchDirectory temporary;
  auto image_path = temporary.path() / "image.json";
  store_document(image_path, image.snapshot());
  auto fingerprint = image.fingerprint();
  std::vector<std::string> arguments;
  auto command = specification.at("command");
  if (!command.is_array() || command.empty())
    throw FlowError("command backend requires an argv array");
  bool image_argument = false;
  for (const auto &argument : command) {
    auto text = argument.get<std::string>();
    image_argument =
        image_argument || text.find("{image}") != std::string::npos;
    substitute(text, "{image}", image_path.string());
    substitute(text, "{entry}", format_address(entry));
    substitute(text, "{image_sha256}", fingerprint);
    arguments.push_back(std::move(text));
  }
  auto protocol = specification.value("protocol", std::string("json"));
  ByteBuffer payload;
  if (protocol == "json") {
    JsonDoc descriptors = JsonDoc::array();
    for (const auto &site : sites)
      descriptors.push_back(json_of_site(site));
    auto parameters = specification;
    parameters.erase("command");
    parameters.erase("known_vectors");
    parameters.erase("protocol");
    parameters["backend"] = "unicorn";
    JsonDoc request = {
        {"protocol_version", 1},        {"image_path", image_path.string()},
        {"image_sha256", fingerprint},  {"entry", format_address(entry)},
        {"input", hex_of_bytes(input)}, {"execution", parameters},
        {"sites", descriptors}};
    auto text = request.dump();
    payload.assign(text.begin(), text.end());
  } else if (protocol == "bytes" || protocol == "hex") {
    if (!image_argument)
      throw FlowError("raw oracle command must receive an {image} argument");
    if (protocol == "hex") {
      auto text = hex_of_bytes(input) + "\n";
      payload.assign(text.begin(), text.end());
    } else
      payload.assign(input.begin(), input.end());
  } else
    throw FlowError("unknown command oracle protocol");
  auto timeout = address_of_json(
      specification.value("command_timeout_milliseconds", JsonDoc(30000u)));
  if (timeout == 0 || timeout > 60000)
    throw FlowError("command timeout must be 1..60000 milliseconds");
  auto process =
      spawn_process(arguments, payload, static_cast<unsigned>(timeout));
  if (process.exit_code != 0)
    throw FlowError("oracle command failed with status " +
                    std::to_string(process.exit_code) + ": " +
                    std::string(process.errors.begin(), process.errors.end()));
  if (protocol != "json") {
    EmulationResult result;
    if (protocol == "hex") {
      std::string encoded(process.output.begin(), process.output.end());
      std::erase_if(encoded, [](unsigned char character) {
        return std::isspace(character) != 0;
      });
      if (encoded.starts_with("0x") || encoded.starts_with("0X"))
        encoded.erase(0, 2);
      result.output = bytes_of_hex(encoded);
    } else
      result.output = process.output;
    if (result.output.size() > 1024 * 1024)
      throw FlowError("raw oracle output exceeds one MiB");
    return result;
  }
  auto response = document_of_bytes(process.output);
  if (response.at("protocol_version") != 1 ||
      response.at("image_sha256") != fingerprint ||
      address_of_json(response.at("entry")) != entry)
    throw FlowError("oracle response does not identify the requested "
                    "candidate image and entry");
  if (!response.value("completed", false))
    throw FlowError("oracle response did not complete execution");
  return execution_of_json(response.at("result"), image);
}
} // namespace armflow
