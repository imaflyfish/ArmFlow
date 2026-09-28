#include <armflow/emulation.hpp>
#include <armflow/subprocess.hpp>
#include <fstream>
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
} // namespace
int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  try {
    ByteBuffer file(24, 0);
    file[0] = 0x41;
    file[1] = 0x42;
    file[2] = 0x43;
    file[3] = 0x44;
    auto nop = word_bytes(0xd503201f),
         ret = word_bytes(0xd65f03c0);
    std::copy(nop.begin(), nop.end(), file.begin() + 16);
    std::copy(ret.begin(), ret.end(), file.begin() + 20);
    JsonDoc mapping = {{"entry", "0x1000"},
                    {"relocated", true},
                    {"regions", JsonDoc::array({{{"begin", "0x1000"},
                                              {"offset", 16},
                                              {"size", 8},
                                              {"label", "code"},
                                              {"executable", true}},
                                             {{"begin", "0x2000"},
                                              {"offset", 0},
                                              {"size", 16},
                                              {"file_size", 4},
                                              {"label", "data"},
                                              {"writable", true}}})},
                    {"functions", JsonDoc::array({{{"begin", "0x1000"},
                                                {"end", "0x1008"},
                                                {"label", "identity"}}})}};
    auto image = BinaryImage::from_flat(file, mapping);
    check(image.regions.size() == 2 && image.functions.size() == 1,
          "explicit flat mappings and function ownership");
    check(image.instruction(0x1000) == 0xd503201f &&
              image.instruction(0x1004) == 0xd65f03c0,
          "flat file offsets map independently of virtual addresses");
    check(image.read(0x2000, 4) == ByteBuffer({'A', 'B', 'C', 'D'}) &&
              image.read(0x2004, 12) == ByteBuffer(12, 0),
          "file prefix plus zero initialized tail");
    check(image.regions[0].source_offset == 16 &&
              image.regions[1].source_offset == 0,
          "flat source offsets retained");
    check(image.valid_target(0x1000) && !image.valid_target(0x2000),
          "flat executable and data permissions remain distinct");
    check(image.relocated &&
              BinaryImage::from_snapshot(image.snapshot()).fingerprint() ==
                  image.fingerprint(),
          "flat images roundtrip through snapshot contract");
    check(EmulationOracle(JsonDoc::object())
                  .run(image, 0x1000, ByteBuffer{37})
                  .returned == 37,
          "native oracle executes independently mapped flat bytes");
    auto bad = mapping;
    bad["regions"][0]["offset"] = 17;
    rejects([&] { BinaryImage::from_flat(file, bad); },
            "flat file overrun refused");
    bad = mapping;
    bad["regions"][0]["size"] = 268435457ULL;
    rejects([&] { BinaryImage::from_flat(file, bad); },
            "flat allocation capped before allocation");
    bad = mapping;
    bad["regions"][0]["file_size"] = 9;
    rejects([&] { BinaryImage::from_flat(file, bad); },
            "stored prefix cannot exceed mapped size");
    bad = mapping;
    bad["regions"][1]["begin"] = "0x1004";
    rejects([&] { BinaryImage::from_flat(file, bad); },
            "overlapping flat virtual regions refused");
    bad = mapping;
    bad["regions"][0]["begin"] = "0xfffffffffffffff8";
    rejects([&] { BinaryImage::from_flat(file, bad); },
            "flat address overflow refused");
    bad = mapping;
    bad["regions"][0]["size"] = 4.5;
    rejects([&] { BinaryImage::from_flat(file, bad); },
            "fractional flat size refused");
    bad = mapping;
    bad["regions"][0]["offset"] = -1;
    rejects([&] { BinaryImage::from_flat(file, bad); },
            "negative flat offset refused");
    bad = mapping;
    bad["functions"][0]["end"] = "0x1010";
    rejects([&] { BinaryImage::from_flat(file, bad); },
            "function cannot extend beyond its mapping");
    bad = mapping;
    bad.erase("relocated");
    check(!BinaryImage::from_flat(file, bad).relocated,
          "flat relocation readiness is not inferred");
    bad = mapping;
    bad["regions"] = JsonDoc::array();
    rejects([&] { BinaryImage::from_flat(file, bad); },
            "empty flat mapping refused");
    bad = mapping;
    bad["regions"][1]["offset"] = 24;
    bad["regions"][1]["file_size"] = 0;
    check(BinaryImage::from_flat(file, bad).read(0x2000, 16) == ByteBuffer(16, 0),
          "explicit zero initialized region may start at file end");
    ScratchDirectory temporary;
    auto input = temporary.path() / "image.bin";
    {
      std::ofstream out(input, std::ios::binary);
      out.write(reinterpret_cast<const char *>(file.data()),
                static_cast<std::streamsize>(file.size()));
    }
    JsonDoc config = {
        {"image", "image.bin"},
        {"flat", mapping},
        {"executable_regions", JsonDoc::array({{{"label", "code"}}})},
        {"execution",
         {{"known_vectors", JsonDoc::array({{{"entry", "0x1000"},
                                          {"input", "25"},
                                          {"output", "2500000000000000"}}})}}}};
    store_document(temporary.path() / "job.json", config);
    auto cli = spawn_process({argv[1], "verify", "--config",
                            (temporary.path() / "job.json").string()},
                           {}, 30000);
    check(cli.exit_code == 0 &&
              document_of_bytes(cli.output).at("passed").get<bool>(),
          "CLI verifies flat mapping with config-relative input file");
    std::cout << passed << " flat-image checks passed; " << failed
              << " failed\n";
    return failed ? 1 : 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
