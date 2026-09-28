#include <armflow/pipeline.hpp>
#include <iostream>
int main(int argc, char **argv) {
  using namespace armflow;
  if (argc != 2)
    return 2;
  try {
    const auto image = BinaryImage::load(argv[1]);
    JsonDoc regions = JsonDoc::array();
    for (const auto &region : image.regions)
      if (region.executable)
        regions.push_back({{"label", region.label}});
    PipelineDriver workflow(image, {{"executable_regions", regions}});
    const auto stage = workflow.stage("plan");
    if (stage.at("sites").empty())
      return 1;
    const auto result = workflow.execute("graph", true);
    const auto restored = workflow.restore(result);
    if (restored.at("restored_sha256") != image.fingerprint())
      return 1;
    std::cout << "Independent installed consumer: " << stage.at("sites").size()
              << " sites; graph transaction and exact restore passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
