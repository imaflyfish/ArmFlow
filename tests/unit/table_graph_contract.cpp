#include "../support/checks.hpp"
#include <armflow/patching.hpp>
#include <iostream>
using namespace armflow;
using namespace armflow_tests;
namespace {
void put(BinaryImage &image, Address at, Address value) {
  ByteBuffer bytes(8);
  for (unsigned i = 0; i < 8; ++i)
    bytes[i] = static_cast<std::uint8_t>(value >> (8 * i));
  image.replace(at, bytes);
}
} // namespace
int main() {
  try {
    BinaryImage image;
    ImageRegion code;
    code.begin = 0x1000;
    code.bytes = ByteBuffer(0x40);
    code.executable = true;
    ImageRegion data;
    data.begin = 0x2000;
    data.bytes = ByteBuffer(0x40);
    image.regions = {code, data};
    image.relocated = true;
    put(image, 0x2000, 0x1010);
    put(image, 0x2008, 0x1020);
    put(image, 0x2010, 0);
    put(image, 0x2018, 0x1030);
    SwitchSite site;
    site.branch = 0x1000;
    site.model = "single_level";
    site.target_table = 0x2000;
    MemoryAccess access;
    access.scale = 3;
    access.width = 8;
    site.target_access = access;
    FlowSettings settings;
    PatchPlan plan;
    auto result = extend_table_graph(image, settings, {site}, plan);
    check(plan.edits.empty() && plan.graph.size() == 2,
          "enumeration adds graph only");
    check(result.at("sites")[0].at("stop") == "invalid target" &&
              !result.at("truncated").get<bool>(),
          "first invalid entry terminates enumeration");
    check(result.at("sites")[0].at("entries")[0].at("evidence") ==
              "table_candidate",
          "table edges are not reported as observed");
    extend_table_graph(image, settings, {site}, plan);
    check(plan.graph.size() == 2, "repeated enumeration deduplicates edges");
    plan = {};
    WordEdit edit;
    edit.site = site.branch;
    plan.edits.push_back(edit);
    result = extend_table_graph(image, settings, {site}, plan);
    check(plan.graph.empty() && result.at("sites").empty(),
          "rewritten site never gains heuristic targets");
    plan = {};
    settings.raw["analysis"]["graph_tables"] = {{"maximum_entries", 1}};
    result = extend_table_graph(image, settings, {site}, plan);
    check(plan.graph.size() == 1 && result.at("truncated").get<bool>(),
          "entry cap explicitly reports truncation");
    settings.raw = JsonDoc::object();
    settings.maximum_targets = 1;
    plan = {};
    result = extend_table_graph(image, settings, {site}, plan);
    check(plan.graph.size() == 1 &&
              result.at("sites")[0].at("stop") == "target cap",
          "unique target cap is enforced");
    settings.maximum_targets = 256;
    image.relocated = false;
    plan = {};
    result = extend_table_graph(image, settings, {site}, plan);
    check(plan.graph.empty(), "unrelocated pointers cannot add graph edges");
    image.relocated = true;
    image.regions[1].writable = true;
    plan = {};
    result = extend_table_graph(image, settings, {site}, plan);
    check(result.at("sites")[0].at("entries")[0].at("mutable") == true,
          "mutable table status remains explicit");
    image.regions[1].readable = false;
    plan = {};
    result = extend_table_graph(image, settings, {site}, plan);
    check(plan.graph.empty(), "unreadable entries are refused");
    image.regions[1].readable = true;
    site.target_table = 0x2038;
    put(image, 0x2038, 0x1010);
    plan = {};
    result = extend_table_graph(image, settings, {site}, plan);
    check(plan.graph.size() == 1 &&
              result.at("sites")[0].at("stop") == "unmapped entry",
          "mapped end stops without overread");
    settings.raw["analysis"]["graph_tables"] = {{"maximum_entries", 0}};
    rejects([&] { extend_table_graph(image, settings, {site}, plan); },
            "zero cap refused");
    settings.raw["analysis"]["graph_tables"] = {{"maximum_entries", 1.5}};
    rejects([&] { extend_table_graph(image, settings, {site}, plan); },
            "fractional cap refused");
    settings.raw["analysis"]["graph_tables"] = {{"enabled", false}};
    plan = {};
    result = extend_table_graph(image, settings, {site}, plan);
    check(result.at("enabled") == false && plan.graph.empty(),
          "table enumeration can be disabled");
    std::cout << passed << " table-graph checks passed; " << failed
              << " failed\n";
    return failed ? 1 : 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
