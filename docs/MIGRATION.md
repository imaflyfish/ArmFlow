# Capability inventory

The table below maps each analysis capability to the native code that provides it
and the contract that exercises it. It is an inventory, not proof of equivalence
on arbitrary inputs.

| Capability | Implementation / exercised contract |
|---|---|
| ISA decode, logical immediates, encoders, backward walk, constants | `opcode_decoder` / `constant_walker`; fixed words, branch limits, W/X semantics, call clobbers, unknown producers and actual assembler fixtures |
| Four artifact families and metadata | typed sites/transitions/flows/plans; strict readers, bounded fields, source/configuration binding and fresh regeneration |
| Two-level and single-level dispatch | explicit executable selection, stack state, signed indices, ADR/ADRP/constants, selects and flag-byte cases |
| OLLVM comparison tree and terminators | bounded tree walk with NZCV path evaluation; constant/conditional back edges, natural fallthrough, padding, compact private-slot cases and liveness refusals |
| State transformations | ordered add/sub/xor/and/or chains, bounded candidate-state worklist, explicit truncation, cycles, signed 32-bit state and observed-state cross-checks |
| P1–P6 | survey → classify → resolve → plan → verified run → graph; library and CLI share the pipeline |
| Table-based switch-view edges | unchanged sites only; instruction-derived stride, bounded first-invalid scan, deduplication and candidate provenance |
| Trace files and external trace process | union all observations; explicit file list, source-bound argv command, process time/output limits; conflicts remain visible |
| Static and emulated resolution | mapped snapshot/ELF/flat memory, explicit relocated status; state-specific native execution sees actual input bytes |
| Native verifier and call shims | fresh Unicorn engine; stack/input/output/TLS/heap; bounded libc models and custom C++ call registry; known outputs, return and coverage checks |
| External verifier | actual candidate snapshot and fingerprint, JSON request/response; legacy bytes/hex mode cannot certify edits without coverage |
| Hazards and self-check | register/NZCV liveness, unmodeled effects, table stability, shared/interior entries, function/range ownership, branch encoding checks |
| Pristine restore / apply | immutable captured source, exact-byte preflight, candidate verification, idempotence, restore only exact original or owned candidate |
| Regression | restore/recompute full plan and skips, rerun outputs; optional minimum edits, maximum skips, exact expected skip set and instruction/target samples |
| Cleanup | literal-LDR/BLR and short reserved filler proposals; normal behavior/coverage gate still required |
| Bulk discovery | `discover` summary plus `batch` grouped by target table/function; independent configurations/results; group failure does not prevent later groups |
| IDA adapter / background boundary | thin snapshot and transaction transport, main-thread `execute_sync` reads/writes, native analysis in an external process; caller may invoke a DatabaseJob from a worker |

## Configuration migration

The new schema is deliberate; old configs are not silently reinterpreted.

| Old field / command | New contract |
|---|---|
| `exec_segments[].name/range` | `executable_regions[].label/range` |
| `mode: switch` | `mode: graph`; linear/full remain available |
| `cff.index_reg_allowlist` | `analysis.index_registers`, numeric register IDs; empty accepts any |
| `cff.state_slot_bases` | `analysis.state_bases`, numeric IDs (29=X29, 31=SP); default [29,31] |
| `cff.dispatch_base_overrides` | `analysis.table_overrides`: site, target and optional index address |
| table scale / `entry_size` | decoded from the actual load instruction; no arbitrary inconsistent stride override |
| `cff.max_switch_entries` | `analysis.graph_tables.maximum_entries`; unique targets also obey `maximum_targets` |
| `cff.ollvm_scan_insns` | bounded known function spans and bounded tree walk, no invented scan beyond a function |
| `cff.scrambler.*` | old example declared these knobs but no old runtime consumed them; new code extracts actual transform operations and bounds expansion explicitly |
| `image` / `reloc_image` / `reloc_base` | one mapped source of truth (ELF, IDA snapshot, explicit flat mapping); already-relocated data belongs to that source snapshot and fingerprint |
| `trace.path` glob | explicit `trace_files` array, paths relative to config; expand chosen files before invoking |
| `trace.command` shell-like string | `trace_command.argv`; placeholders `{image}`, `{image_sha256}`, `{entry}`; response must bind source hash |
| `verifier.*` | `execution.*`; input/output modes, imports, models and memory documented in CONFIG.md |
| `iat` external JSON | inline `execution.imports` map; library callers can load a map before construction |
| `strict_orig_check: false` / `--no-strict` | removed; exact source and instruction comparison is mandatory |
| `jobs` | consumed by `batch`: name, functions, optional analysis/execution/regression/mode overrides |
| `regression.baseline` | `regression.minimum_edits` and `maximum_skips` (instruction counts, not an ambiguous patched-site count) |
| `skip_expectations` / `samples` | `expected_skips` exact site/arrival/reason records; `instruction_samples` address + word/operation/target |
| `--parent-fn` / `--in` / `--out` | `--function` / `--from` / `--output` |
| `--source emu` | `analysis.emulate: true`; trace evidence is supplied explicitly |
| separate phase files with fixed cwd names | explicit output paths and source-bound stage envelopes |
| standalone apply / run / switch / clean / revert | aliases remain; no write intent means preview; contradictory flags are rejected |
| background result-file helper | caller-owned worker invokes DatabaseJob; use save_receipt for recoverable ownership; no analysis code in Python |

## Intentional refusal and limitations

Old cleanup heuristics could directly change bytes without executing them; the new
API always preserves the verification gate. A dead camouflage path that has never
executed cannot satisfy coverage. Unproven tree/register/state effects retain their
original bytes. Table enumeration reports candidates, not natural execution.

A batch output contains separate candidates from the same input. It is not a merged
image. Each group includes its scoped configuration and independently restorable
receipt. To apply several jobs to a live IDA database, capture a fresh DatabaseJob
for each sequential function scope and restore completed receipts in reverse order.

IDA chunk ranges remain separate; analysis does not invent ownership across gaps or
merge shared tails. Linux and Windows runtime validation, arbitrary target-binary
coverage, complete libc/OS emulation, on-device backends, EH/stack reconstruction
and formal equivalence proofs are outside this local validated result. `ondevice`
and EH reconstruction were not implemented baseline functionality.
