#include <armflow/emulation.hpp>
#include <armflow/subprocess.hpp>
namespace armflow {
JsonDoc gather_external_trace(const BinaryImage &image,
                              const JsonDoc &configuration) {
  if (!configuration.is_object())
    throw FlowError("trace_command requires an object");
  const auto &command = configuration.at("argv");
  if (!command.is_array() || command.empty() || command.size() > 256)
    throw FlowError("trace_command.argv requires 1..256 arguments");
  const auto timeout = address_of_json(configuration.value(
      "timeout_milliseconds", JsonDoc(default_process_timeout_milliseconds)));
  if (!timeout || timeout > maximum_process_timeout_milliseconds)
    throw FlowError("trace timeout must be in 1.." +
                    std::to_string(maximum_process_timeout_milliseconds) +
                    " milliseconds");
  ScratchDirectory temporary;
  const auto path = temporary.path() / "source.json";
  store_document(path, image.snapshot());
  const auto fingerprint = image.fingerprint();
  const auto entry =
      address_of_json(configuration.value("entry", JsonDoc(image.entry)));
  std::vector<std::string> arguments;
  for (const auto &item : command) {
    auto value = item.get<std::string>();
    for (const auto &[key, replacement] : std::map<std::string, std::string>{
             {"{image}", path.string()},
             {"{image_sha256}", fingerprint},
             {"{entry}", format_address(entry)}}) {
      std::size_t position = 0;
      while ((position = value.find(key, position)) != std::string::npos) {
        value.replace(position, key.size(), replacement);
        position += replacement.size();
      }
    }
    arguments.push_back(std::move(value));
  }
  const auto payload = JsonDoc({{"protocol_version", 1},
                                {"source_sha256", fingerprint},
                                {"image_path", path.string()},
                                {"entry", format_address(entry)}})
                           .dump();
  auto response = spawn_process(
      arguments,
      {reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()},
      static_cast<unsigned>(timeout));
  if (response.exit_code)
    throw FlowError("trace command exited unsuccessfully: " +
                    std::to_string(response.exit_code));
  auto document = document_of_bytes(response.output);
  if (!document.is_object() ||
      document.at("source_sha256").get<std::string>() != fingerprint)
    throw FlowError("trace command response belongs to a different image");
  SurveyObservations observations;
  observations.merge(document.at("observations"));
  return observations.json();
}
} // namespace armflow
