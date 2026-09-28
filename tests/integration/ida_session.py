"""Run inside a freshly created IDA database for samples/switch_cases.S."""
import copy
import json
import os
from pathlib import Path
import sys
import traceback

import ida_auto
import ida_bytes
import ida_idaapi
import ida_kernwin
import ida_name
import ida_pro
import ida_xref

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root / "integrations" / "ida"))
import armflow_bridge as bridge

output = Path(os.environ.get("ARMFLOW_EVIDENCE", str(root / "build" / "ida-evidence")))
output.mkdir(parents=True, exist_ok=True)
checks = []


def check(condition, name):
    checks.append({"name": name, "passed": bool(condition)})
    if not condition:
        raise AssertionError(name)


def rejects(action, name):
    try:
        action()
    except bridge.BridgeError:
        check(True, name)
        return
    check(False, name)


def number(value):
    return (value & ((1 << 64) - 1)).to_bytes(8, "little").hex()


def address(name):
    result = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
    if result == ida_idaapi.BADADDR:
        raise RuntimeError("missing assembled function " + name)
    return result


def main():
    ida_auto.auto_wait()
    vectors = []
    for name in ("two_constant", "two_choice", "single_choice", "compare_tree"):
        for value in (0, 1):
            expected = value + 7 if name == "two_constant" else (7 if value == 0 else value - 3) if name == "two_choice" else value + (11 if value == 0 else 19) if name == "single_choice" else value + 2
            vectors.append({"entry": hex(address(name)), "input": number(value), "output": number(expected)})
    for value in (0, 1):
        vectors.append({"entry": hex(address("bit_selected")), "input": bytes([value]).hex(),
                        "output": number(43 if value else 41), "input_spec": {"mode": "bytes"}})
    config = {"mode": "linear", "executable_regions": [{"label": ".text"}],
              "analysis": {"emulate": True}, "execution": {"known_vectors": vectors}}
    binary = root / "build" / "debug" / "arm-flow"
    original = bridge.snapshot()
    check(len(original["functions"]) == 7, "real IDA exports seven function ranges")
    job = bridge.DatabaseJob(binary, config)
    preview = job.preview()
    check(not preview["applied"] and preview["plan"]["edits"], "native preview contains concrete edits")
    check(bridge.snapshot() == original, "preview preserves complete IDA snapshot")
    receipt = job.apply()
    check(receipt["native"]["verification"]["passed"], "native candidate vectors pass before host submit")
    for edit in receipt["native"]["plan"]["edits"]:
        check(ida_bytes.get_bytes(int(edit["address"], 16), 4).hex() == edit["replacement"], "IDA contains a verified replacement instruction")
    check(job.apply() == receipt, "repeated host application is idempotent")
    job.save_receipt(output / "ida-saved-receipt.json")
    resumed = bridge.DatabaseJob.resume(binary, output / "ida-saved-receipt.json")
    edit = receipt["native"]["plan"]["edits"][0]
    target = int(edit["address"], 16)
    ida_bytes.patch_bytes(target, bytes.fromhex("1f2003d5"))
    rejects(resumed.restore, "restore refuses unrelated changed instruction")
    check(ida_bytes.get_bytes(target, 4).hex() == "1f2003d5", "failed restore leaves drifted bytes intact")
    ida_bytes.patch_bytes(target, bytes.fromhex(edit["replacement"]))
    check(resumed.restore()["restored"], "saved receipt resumes and restores through native source check")
    check(bridge.snapshot() == original, "restoration recovers exact original IDA memory and user references")
    check(resumed.restore()["already_restored"], "host restore is idempotent")
    fake = copy.deepcopy(receipt)
    fake["host_added_edges"].append({"source": hex(address("two_constant")), "target": hex(address("two_choice"))})
    rejects(lambda: job.restore(fake), "forged host ownership log is refused")
    # Fail after a byte was actually written; rollback must include that write.
    write = ida_bytes.patch_bytes
    triggered = False
    def fail_after_write(location, data):
        nonlocal triggered
        write(location, data)
        if not triggered:
            triggered = True
            raise RuntimeError("injected host write failure after actual mutation")
    ida_bytes.patch_bytes = fail_after_write
    try:
        rejects(lambda: bridge.DatabaseJob(binary, config).apply(), "injected byte failure is caught")
    finally:
        ida_bytes.patch_bytes = write
    check(triggered and bridge.snapshot() == original, "injected byte failure leaves no partial transaction")
    # A pre-existing user edge must survive graph apply and restore.
    edge = preview["plan"]["graph"][0]
    source, destination = int(edge["source"], 16), int(edge["target"], 16)
    check(ida_xref.add_cref(source, destination, ida_xref.fl_JN | ida_xref.XREF_USER), "prepare pre-existing user graph edge")
    prior = bridge.snapshot()
    graph_config = copy.deepcopy(config)
    graph_config["mode"] = "graph"
    graph_job = bridge.DatabaseJob(binary, graph_config)
    graph = graph_job.apply("graph")
    check(edge not in graph["host_added_edges"], "pre-existing user edge is not claimed by the transaction")
    check(not graph["native"]["plan"]["edits"], "graph mode preserves all code bytes")
    graph_job.restore()
    check(bridge.snapshot() == prior, "graph restore preserves prior user references")
    add = ida_xref.add_cref
    triggered = False
    def fail_after_edge(frm, to, kind):
        nonlocal triggered
        result = add(frm, to, kind)
        if not triggered:
            triggered = True
            return False
        return result
    ida_xref.add_cref = fail_after_edge
    try:
        rejects(lambda: bridge.DatabaseJob(binary, graph_config).apply("graph"), "injected reference failure is caught")
    finally:
        ida_xref.add_cref = add
    check(triggered and bridge.snapshot() == prior, "reference failure rolls back only new edges")
    ida_xref.del_cref(source, destination, False)
    check(bridge.snapshot() == original, "fixture database ends with original memory and user references")
    (output / "ida-original-snapshot.json").write_text(json.dumps(original, indent=2))
    (output / "ida-native-applied.json").write_text(json.dumps(receipt["native"], indent=2))


status = 0
failure = None
try:
    main()
except BaseException:
    status = 1
    failure = traceback.format_exc()
    print(failure)
(output / "ida-integration.json").write_text(json.dumps({"ida_version": ida_kernwin.get_kernel_version(), "checks": checks,
                                                          "passed": status == 0, "failure": failure}, indent=2))
ida_pro.qexit(status)
