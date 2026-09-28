# Validation scope

This directory describes how to verify a checkout of ArmFlow. It publishes no
recorded run: counts and transcripts belong to the machine that ran them, so run
the suites yourself and read your own output.

## Suites

```sh
cmake --preset debug   && cmake --build --preset debug   && ctest --preset debug --verbose
cmake --preset release && cmake --build --preset release && ctest --preset release --verbose
cmake --preset sanitize && cmake --build --preset sanitize && ctest --preset sanitize --verbose
```

The test build assembles the neutral AArch64 fixtures in `samples/*.S` with a
cross-target LLVM compiler and ELF linker. Without `clang` and `ld.lld` for
`aarch64-none-elf`, the fixture-dependent tests are not configured and the rest
of the suite still runs.

Coverage spans instruction decoding and constant tracking, two-level and
single-level table dispatch, comparison-tree recovery, bounded state expansion,
static and observed target grading, native Unicorn execution, branch planning,
the rewrite transaction, artifact readers, command oracles, libc call shims and
the regression and cleanup paths.

## IDA bridge

`integrations/ida/` carries an IDAPython bridge and a host script. Reproduce its
checks on a **fresh disposable database built from the owned assembly fixture**,
never on an existing user session — see
[`integrations/ida/README.md`](../integrations/ida/README.md). The bridge is a
transport: it exports a snapshot, asks the native program to analyze it, and
applies accepted byte edits or graph references on IDA's main thread.

## Limits

Candidate verification runs the original and modified image separately, checks
known outputs and requires coverage of the changed instructions and the proposed
indirect-branch targets. Finite examples do not establish equivalence over all
inputs, and a passing suite does not license rewriting an arbitrary binary.
Linux and Windows execution are unverified.
