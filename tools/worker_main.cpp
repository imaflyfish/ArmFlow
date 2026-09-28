#include <armflow/emulation.hpp>
#include <iostream>
using namespace armflow;
int main(int argc, char **argv) {
  try {
    if (argc > 1 && std::string(argv[1]) == "--help") {
      std::cout << "arm-oracle-worker reads one protocol-v1 JSON request on "
                   "stdin and executes the supplied snapshot with Unicorn.\n";
      return 0;
    }
    ByteBuffer bytes;
    char buffer[4096];
    while (std::cin) {
      std::cin.read(buffer, sizeof(buffer));
      auto count = std::cin.gcount();
      if (count > 0) {
        if (bytes.size() + static_cast<std::size_t>(count) > 8 * 1024 * 1024)
          throw FlowError("request size limit exceeded");
        bytes.insert(bytes.end(), buffer, buffer + count);
      }
    }
    auto request = document_of_bytes(bytes);
    if (request.at("protocol_version") != 1)
      throw FlowError("unsupported oracle protocol");
    auto image = BinaryImage::load(request.at("image_path").get<std::string>());
    if (image.fingerprint() != request.at("image_sha256").get<std::string>())
      throw FlowError("request image hash mismatch");
    auto entry = address_of_json(request.at("entry"));
    auto input = bytes_of_hex(request.at("input"));
    auto specification = request.at("execution");
    specification["backend"] = "unicorn";
    std::vector<SwitchSite> sites;
    for (const auto &value : request.at("sites"))
      sites.push_back(site_of_json(value));
    EmulationOracle oracle(specification);
    auto result = oracle.run(image, entry, input, sites);
    JsonDoc response = {{"protocol_version", 1},
                     {"image_sha256", image.fingerprint()},
                     {"entry", format_address(entry)},
                     {"completed", true},
                     {"result", json_of_execution(result)}};
    std::cout << response.dump() << '\n';
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "oracle-worker: " << error.what() << '\n';
    return 2;
  }
}
