# IDA 9 host bridge

The native C++ program owns analysis and candidate verification. IDAPython exports
host memory and metadata, invokes that program, and applies its verified changes
on IDA's main thread. No existing user database was used for integration testing.

Load `armflow_bridge.py` into IDA's Python path, then create an explicit job:

```python
import armflow_bridge as bridge
job = bridge.DatabaseJob("/absolute/path/to/arm-flow", {
    "mode": "graph",
    "executable_regions": [{"label": ".text"}]
})
proposal = job.preview()
receipt = job.apply("graph")
job.save_receipt("/absolute/path/to/session.json")
job.restore()
```

For byte edits use linear/full mode with execution known vectors and `job.apply()`.
The bridge does not infer arguments, expected outputs, imports or executable
segments. Embedded configs are materialized dictionaries; inline observations are
accepted, while CLI-relative image/trace-file paths are not.

A new snapshot is compared with the captured original immediately before writing.
Every byte and actual newly-added user graph edge is logged. Already-existing
references are never claimed. Submission failures roll back the actual changes,
including a host call which wrote a byte before raising. Restore rejects unrelated
drift and checks native source/plan integrity before using the host log. Saved
sessions can be resumed with `DatabaseJob.resume(binary, session_path)`.

Snapshots retain user code references; automatic instruction edges are rebuilt
by the C++ decoder. The bridge neither claims ownership of automatic references
nor deletes them during restore. Function chunks are exported as separate explicit
ranges; shared chunks are deduplicated. Reanalysis is not forced during the atomic
transaction: later user changes to function ranges or references are detected as
state drift. Call models do not supply IDA decompiler or switch-info reconstruction.

`tests/integration/ida_session.py` runs inside IDA 9.4 against the independently
assembled dispatch fixture. It checks preview, actual byte application, repeated
application, saved-receipt restore, unrelated drift, forged ownership logs,
pre-existing graph references and injected byte and reference failures.

Two limits are structural rather than incidental. The script drives the Debug
executable, so it says nothing about Release host behavior. And it uses one owned
fixture on a database built for it, so it says nothing about arbitrary target
binaries or about databases that already hold user work. Never point it at an
existing session.

## Reproduce the owned fixture checks

Build the Debug preset from the repository root as described in the main README.
It produces `build/debug/arm-flow` and `build/debug/switch_cases.elf`.
Open that ELF in a **fresh disposable IDA 9.4 database** and let analysis finish.
In that IDA instance's Python console, run the checked-in test script:

```python
import os
import tempfile
from pathlib import Path

os.environ["ARMFLOW_EVIDENCE"] = tempfile.mkdtemp(prefix="armflow-ida-check-")
print("Evidence directory:", os.environ["ARMFLOW_EVIDENCE"])
script = Path("/absolute/path/to/ArmFlow/tests/integration/ida_session.py")
exec(compile(script.read_text(encoding="utf-8"), str(script), "exec"),
     {"__file__": str(script), "__name__": "__main__"})
```

The script modifies and restores only this disposable fixture database, writes
`ida-integration.json` and related receipts to the printed directory, and exits
that IDA instance with its test status. Read the result's `passed`, `failure` and
individual `checks` fields. Running a newer checkout produces new evidence; the
published results apply to their recorded source and executable hashes. The
2026-09-23 result remains historical, and each 2026-09-25 result covers only its
recorded Debug binary.
