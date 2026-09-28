# Implementation

ArmFlow 1.0.0 keeps all analysis, configuration, instruction handling, constant
tracking, state propagation, native execution, call shims, planning, verification,
artifact binding and workflow logic in C++20. IDAPython contains only host export,
subprocess and database transaction transport. Standard AArch64 and IDA interfaces
and inherited license notices retain their original names.

The capability inventory is MIGRATION.md; how to run the suites is in
../validation/README.md. The IDA bridge is checked against one owned fixture on a
disposable database, which establishes neither Release host behavior nor
arbitrary-target coverage.

Unknown effects, table instability, shared/interior entries, uncovered edited
instructions and uncovered candidate branch outcomes prevent byte commitment.
Comparison tree, native state chains, graph candidates, external observations,
regression expectations and batch isolation have concrete fixtures and refusal
cases. Restore regenerates the expected plan and metadata ownership from the
immutable captured source; it refuses unrelated drift.

The exported CMake target is ArmFlow::armflow. Dependencies and license texts
accompany the source and installed package. Nothing here claims universal
deobfuscation or formal program equivalence.
