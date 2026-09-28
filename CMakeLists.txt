cmake_minimum_required(VERSION 3.24)
project(ArmFlow VERSION 1.0.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
option(ARMFLOW_SANITIZE "Enable ASan and UBSan" OFF)
option(ARMFLOW_FUZZ "Build the libFuzzer entry" OFF)
find_package(nlohmann_json 3.12 REQUIRED)
find_package(yaml-cpp 0.8 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED IMPORTED_TARGET capstone>=5.0)
pkg_check_modules(UNICORN REQUIRED IMPORTED_TARGET unicorn>=2.1)
pkg_check_modules(GCRYPT REQUIRED IMPORTED_TARGET libgcrypt>=1.10)
add_library(armflow src/image/binary_image.cpp src/aarch64/opcode_decoder.cpp src/aarch64/constant_walker.cpp src/flow/switch_survey.cpp src/flow/transition_classifier.cpp src/flow/target_resolver.cpp src/report/artifact_writer.cpp src/emulation/emulation_oracle.cpp src/patching/patch_planner.cpp src/patching/patch_transaction.cpp src/system/process_spawn.cpp src/report/artifact_reader.cpp src/emulation/command_oracle.cpp)
target_include_directories(armflow PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_compile_features(armflow PUBLIC cxx_std_20)
target_link_libraries(armflow PUBLIC nlohmann_json::nlohmann_json PRIVATE PkgConfig::GCRYPT PkgConfig::CAPSTONE PkgConfig::UNICORN yaml-cpp::yaml-cpp)
target_compile_options(armflow PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
if(ARMFLOW_SANITIZE)
 target_compile_options(armflow PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
 target_link_options(armflow PUBLIC -fsanitize=address,undefined)
endif()
add_executable(arm-flow app/cli_main.cpp)
target_sources(armflow PRIVATE src/app/pipeline_driver.cpp src/app/regression_checks.cpp src/app/batch_driver.cpp)
target_sources(armflow PRIVATE src/emulation/call_shims.cpp src/emulation/trace_source.cpp)
target_sources(armflow PRIVATE src/patching/cleanup_proposals.cpp)
target_sources(armflow PRIVATE src/flow/state_expansion.cpp src/flow/table_graph.cpp)
target_link_libraries(arm-flow PRIVATE armflow)
include(CTest)
if(BUILD_TESTING)
 add_executable(flow-core-tests tests/unit/foundation_contract.cpp)
 target_link_libraries(flow-core-tests PRIVATE armflow)
 add_test(NAME foundation-contract COMMAND flow-core-tests)
 add_executable(flow-cleanup-tests tests/unit/cleanup_contract.cpp)
 target_link_libraries(flow-cleanup-tests PRIVATE armflow)
 add_test(NAME cleanup-contract COMMAND flow-cleanup-tests)
 add_executable(flow-graph-tests tests/unit/table_graph_contract.cpp)
 target_link_libraries(flow-graph-tests PRIVATE armflow)
 add_test(NAME table-graph-contract COMMAND flow-graph-tests)
 add_executable(flow-flat-tests tests/unit/flat_image_contract.cpp)
 target_link_libraries(flow-flat-tests PRIVATE armflow)
 add_dependencies(flow-flat-tests arm-flow)
 add_test(NAME flat-image-contract COMMAND flow-flat-tests $<TARGET_FILE:arm-flow>)
endif()
if(BUILD_TESTING)
 find_program(ARMFLOW_CROSS_CLANG clang HINTS /opt/homebrew/opt/llvm/bin)
 find_program(ARMFLOW_ELF_LINKER ld.lld HINTS /opt/homebrew/opt/lld/bin)
 if(ARMFLOW_CROSS_CLANG AND ARMFLOW_ELF_LINKER)
  add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/switch_cases.elf
   COMMAND ${ARMFLOW_CROSS_CLANG} --target=aarch64-none-elf -nostdlib -fuse-ld=${ARMFLOW_ELF_LINKER}
    -Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/samples/layout.ld ${CMAKE_CURRENT_SOURCE_DIR}/samples/switch_cases.S -o ${CMAKE_CURRENT_BINARY_DIR}/switch_cases.elf
   DEPENDS samples/switch_cases.S samples/layout.ld VERBATIM)
  add_custom_target(dispatch-fixtures ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/switch_cases.elf)
  add_executable(flow-pipeline-tests tests/integration/sample_pipeline.cpp)
  target_link_libraries(flow-pipeline-tests PRIVATE armflow)
  add_dependencies(flow-pipeline-tests dispatch-fixtures)
  add_test(NAME sample-pipeline COMMAND flow-pipeline-tests ${CMAKE_CURRENT_BINARY_DIR}/switch_cases.elf)
 endif()
endif()
if(ARMFLOW_FUZZ)
 target_compile_options(armflow PRIVATE -fsanitize=fuzzer-no-link)
 add_executable(flow-fuzz tests/fuzz/flow_driver.cpp)
 target_compile_options(flow-fuzz PRIVATE -fsanitize=fuzzer)
 target_link_options(flow-fuzz PRIVATE -fsanitize=fuzzer)
 target_link_libraries(flow-fuzz PRIVATE armflow)
endif()

add_executable(arm-oracle-worker tools/worker_main.cpp)
target_link_libraries(arm-oracle-worker PRIVATE armflow)
if(BUILD_TESTING AND TARGET dispatch-fixtures)
 add_executable(flow-contract-tests tests/integration/contracts.cpp)
 target_link_libraries(flow-contract-tests PRIVATE armflow)
 add_dependencies(flow-contract-tests dispatch-fixtures arm-oracle-worker)
 add_test(NAME artifact-process-contract COMMAND flow-contract-tests ${CMAKE_CURRENT_BINARY_DIR}/switch_cases.elf $<TARGET_FILE:arm-oracle-worker>)
 add_executable(flow-workflow-tests tests/integration/pipeline.cpp)
 target_link_libraries(flow-workflow-tests PRIVATE armflow)
 add_dependencies(flow-workflow-tests dispatch-fixtures arm-flow)
 add_test(NAME workflow-contract COMMAND flow-workflow-tests ${CMAKE_CURRENT_BINARY_DIR}/switch_cases.elf $<TARGET_FILE:arm-flow>)
 add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/call_cases.elf
  COMMAND ${ARMFLOW_CROSS_CLANG} --target=aarch64-none-elf -nostdlib -fuse-ld=${ARMFLOW_ELF_LINKER}
   -Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/samples/layout.ld -Wl,-e,copy_roundtrip ${CMAKE_CURRENT_SOURCE_DIR}/samples/call_cases.S -o ${CMAKE_CURRENT_BINARY_DIR}/call_cases.elf
  DEPENDS samples/call_cases.S samples/layout.ld VERBATIM)
 add_custom_target(call-fixtures ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/call_cases.elf)
 add_executable(flow-call-tests tests/integration/call_shims.cpp)
 target_link_libraries(flow-call-tests PRIVATE armflow)
 add_dependencies(flow-call-tests call-fixtures arm-oracle-worker)
 add_test(NAME call-model-contract COMMAND flow-call-tests ${CMAKE_CURRENT_BINARY_DIR}/call_cases.elf $<TARGET_FILE:arm-oracle-worker>)
 add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/tree_cases.elf
  COMMAND ${ARMFLOW_CROSS_CLANG} --target=aarch64-none-elf -nostdlib -fuse-ld=${ARMFLOW_ELF_LINKER}
   -Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/samples/layout.ld -Wl,-e,tree_compact ${CMAKE_CURRENT_SOURCE_DIR}/samples/tree_cases.S -o ${CMAKE_CURRENT_BINARY_DIR}/tree_cases.elf
  DEPENDS samples/tree_cases.S samples/layout.ld VERBATIM)
 add_custom_target(tree-fixtures ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/tree_cases.elf)
 add_executable(flow-tree-tests tests/integration/tree_pipeline.cpp)
 target_link_libraries(flow-tree-tests PRIVATE armflow)
 add_dependencies(flow-tree-tests tree-fixtures)
 add_test(NAME tree-pipeline COMMAND flow-tree-tests ${CMAKE_CURRENT_BINARY_DIR}/tree_cases.elf)
 add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/state_cases.elf
  COMMAND ${ARMFLOW_CROSS_CLANG} --target=aarch64-none-elf -nostdlib -fuse-ld=${ARMFLOW_ELF_LINKER}
   -Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/samples/layout.ld -Wl,-e,state_chain ${CMAKE_CURRENT_SOURCE_DIR}/samples/state_cases.S -o ${CMAKE_CURRENT_BINARY_DIR}/state_cases.elf
  DEPENDS samples/state_cases.S samples/layout.ld VERBATIM)
 add_custom_target(state-fixtures ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/state_cases.elf)
 add_executable(flow-state-tests tests/integration/state_pipeline.cpp)
 target_link_libraries(flow-state-tests PRIVATE armflow)
 add_dependencies(flow-state-tests state-fixtures)
 add_test(NAME state-pipeline COMMAND flow-state-tests ${CMAKE_CURRENT_BINARY_DIR}/state_cases.elf)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
install(TARGETS armflow arm-flow arm-oracle-worker
 EXPORT ArmFlowTargets
 ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
 LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
 RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY docs integrations licenses examples samples validation
 DESTINATION ${CMAKE_INSTALL_DATADIR}/ArmFlow
 PATTERN "__pycache__" EXCLUDE)
install(FILES README.md LICENSE THIRD_PARTY_NOTICES.md dependencies.lock.json
 DESTINATION ${CMAKE_INSTALL_DATADIR}/ArmFlow)
configure_package_config_file(cmake/ArmFlowConfig.cmake.in
 ${CMAKE_CURRENT_BINARY_DIR}/ArmFlowConfig.cmake
 INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ArmFlow)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/ArmFlowConfigVersion.cmake
 VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ArmFlowConfig.cmake
 ${CMAKE_CURRENT_BINARY_DIR}/ArmFlowConfigVersion.cmake
 DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ArmFlow)
install(EXPORT ArmFlowTargets NAMESPACE ArmFlow::
 DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ArmFlow)
