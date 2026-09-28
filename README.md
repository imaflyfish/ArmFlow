# ArmFlow

A C++20 library and CLI for AArch64 dispatch analysis, control-flow reports and
same-size branch rewriting gated by known-vector and coverage checks.
Version 1.0.0 targets macOS arm64. How to run the suites and what they do and do
not establish is in the [validation scope](validation/README.md).

The CLI produces reports and candidate snapshots without overwriting input files.
The optional IDAPython bridge exports an IDA database, asks the native program to
analyze it, and submits accepted byte edits or candidate graph references on IDA's main thread.
This is a new workflow and configuration schema, not a drop-in Python API replacement.

The native library currently provides mapped ELF64/snapshot/flat-file inputs, instruction
semantics, bounded constant and binary-choice tracking, two-level and single-level
table dispatch analysis, experimental comparison-tree recovery, static and observed
target grading, native Unicorn execution, branch planning and an in-memory rewrite
transaction. The CLI now includes source-bound staged artifacts, full workflow, graph ownership,
restore/regression, command oracles, bounded libc call models and cleanup proposals.
Comparison-tree conditional back edges, bounded state expansion, table graph
candidates, external traces, independent batch jobs and regression expectations
are implemented and exercised. See the [migration inventory](docs/MIGRATION.md).

Candidate verification executes the original and modified image separately, checks
known outputs and requires coverage of changed instructions and the proposed
indirect-branch targets. Finite examples do not establish equivalence for all inputs.
The library rejects unsupported reasoning cases instead of substituting a guess.

## Development build

Validated local dependencies are available with Homebrew:

```sh
brew install cmake ninja pkgconf nlohmann-json libgcrypt capstone unicorn yaml-cpp llvm lld
cmake --preset debug
cmake --build --preset debug
ctest --preset debug --verbose
```

The test build compiles the neutral AArch64 assembly in `samples/switch_cases.S`
using a cross-target LLVM compiler and ELF linker; without `clang` and `ld.lld`
for `aarch64-none-elf` the fixture-dependent tests are not configured and the
rest of the suite still runs.

The IDA bridge is exercised separately, against a **fresh disposable database
built from the owned assembly fixture** — byte and graph application, restoration
and injected host failures. That covers one fixture, not arbitrary existing
databases. See the [IDA bridge guide](integrations/ida/README.md) to reproduce it.
Linux and Windows execution are unverified. How to run everything is in
[validation/README.md](validation/README.md).

Current development commands:

```sh
build/debug/arm-flow decode 0xb8a95948 0x100000
build/debug/arm-flow snapshot build/debug/switch_cases.elf snapshot.json
build/debug/arm-flow resolve --image build/debug/switch_cases.elf --config samples/settings.json --output analysis.json
build/debug/arm-flow run --config samples/workflow.json --output build/preview.json
build/debug/arm-flow run --config samples/workflow.json --apply --output build/applied.json
build/debug/arm-flow regress --config samples/workflow.json --output build/regression.json
build/debug/arm-flow restore --config samples/workflow.json --from build/applied.json --output build/restored.json
```

`survey` and `classify` select earlier stages. `--from` checks a prior stage against
fresh source/configuration analysis. The CLI returns separate snapshots; the thin
IDA adapter explicitly submits verified changes to its database. Read
[configuration and protocol details](docs/CONFIG.md), the [IDA bridge guide](integrations/ida/README.md),
and the [validation scope](validation/README.md).

## Sources and licensing

The switch-flattening approach follows DumpA1n's MIT-licensed
[unflatten64](https://github.com/DumpA1n/unflatten64), whose copyright notice is
retained in `licenses/unflatten64-MIT.txt`. Analysis, verification and the host
transport are implemented here. The IDA checks cover one owned fixture, not every
workflow or arbitrary binaries, and finite checks do not prove that a rewritten
branch matches every input.

Implementation: copyright 2026 imaflyfish, licensed under GPL-2.0-only. The
native build links Unicorn; this distribution retains its GPL license together
with dependency notices. No third-party target binaries or private target data
are included in the source tree.

## Install and use the library

```sh
cmake --preset release
cmake --build --preset release
ctest --preset release --verbose
cmake --install build/release --prefix "$PWD/dist/ArmFlow-macos-arm64"
cmake -S examples/consumer -B build/consumer -DCMAKE_PREFIX_PATH="$PWD/dist/ArmFlow-macos-arm64"
cmake --build build/consumer
build/consumer/consumer build/release/switch_cases.elf
```

The installed CMake target is `ArmFlow::armflow`. Native binary archives
include the program, worker, static library, headers, host adapter, docs, examples
and licenses. Homebrew runtime dependencies are installed separately; the archive
is not a self-contained macOS application. Validated dependency versions are in
`dependencies.lock.json`.

How to run the suites and what they cover: [validation/README.md](validation/README.md).
