"""IDA host transport for ArmFlow; all analysis/verification stays in C++.

Load this module in IDA 9.x, then construct DatabaseJob(native_binary, config).
preview() is read-only; apply() executes the native verification gate before
submitting an atomic host transaction. restore() requires its exact host receipt.
Snapshots include user code references; automatic instruction references are
reconstructed by the native decoder and are never claimed as bridge-owned.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile

import ida_auto
import ida_bytes
import ida_funcs
import ida_ida
import ida_kernwin
import ida_nalt
import ida_segment
import ida_xref
import idautils


class BridgeError(RuntimeError):
    pass


def _main(action, write=False):
    result = []
    failure = []

    def invoke():
        try:
            result.append(action())
        except BaseException as error:
            failure.append(error)
        return 1

    status = ida_kernwin.execute_sync(
        invoke, ida_kernwin.MFF_WRITE if write else ida_kernwin.MFF_READ
    )
    if failure:
        raise failure[0]
    if status == -1 or not result:
        raise BridgeError("IDA did not execute the requested main-thread operation")
    return result[0]


def _references(address):
    return [item for item in idautils.XrefsFrom(address, ida_xref.XREF_ALL)
            if item.iscode and (item.type & ida_xref.XREF_MASK) != ida_xref.fl_F]


def _has_reference(source, target):
    return any(item.to == target for item in _references(source))


def _snapshot():
    if not ida_ida.inf_is_64bit() or ida_ida.inf_is_be() or ida_ida.inf_get_procname().lower() != "arm":
        raise BridgeError("the active database must contain little-endian AArch64 code")
    regions, functions, references = [], [], []
    total = 0
    segment = ida_segment.get_first_seg()
    while segment:
        length = segment.end_ea - segment.start_ea
        total += length
        if length <= 0 or total > 256 * 1024 * 1024:
            raise BridgeError("database snapshot exceeds the 256 MiB image limit")
        data = ida_bytes.get_bytes(segment.start_ea, length)
        if data is None or len(data) != length:
            raise BridgeError("unable to read a complete database segment")
        regions.append({"begin": hex(segment.start_ea), "bytes": data.hex(),
                        "label": ida_segment.get_segm_name(segment),
                        "readable": bool(segment.perm & ida_segment.SEGPERM_READ),
                        "writable": bool(segment.perm & ida_segment.SEGPERM_WRITE),
                        "executable": bool(segment.perm & ida_segment.SEGPERM_EXEC),
                        "source_offset": None})
        if segment.perm & ida_segment.SEGPERM_EXEC:
            for address in idautils.Heads(segment.start_ea, segment.end_ea):
                for reference in _references(address):
                    if reference.user:
                        references.append({"source": hex(address), "target": hex(reference.to), "owned": False})
        segment = ida_segment.get_next_seg(segment.start_ea)
    for start in idautils.Functions():
        function = ida_funcs.get_func(start)
        chunks = list(idautils.Chunks(start))
        # Separate chunks remain explicit ranges. Never pretend gaps belong to
        # executable instructions of this function or invent missing bytes.
        for index, (begin, end) in enumerate(chunks):
            label = ida_funcs.get_func_name(start)
            if index:
                label += ":chunk:" + hex(begin)
            functions.append({"begin": hex(begin), "end": hex(end), "label": label})
    functions.sort(key=lambda item: (int(item["begin"], 16), int(item["end"], 16)))
    # A shared tail can appear in several IDA function chunk enumerations.
    unique = {}
    for function in functions:
        unique.setdefault((function["begin"], function["end"]), function)
    references.sort(key=lambda item: (int(item["source"], 16), int(item["target"], 16)))
    return {"schema_version": 1, "architecture": "aarch64",
            "entry": hex(ida_ida.inf_get_start_ea()), "relocated": True,
            "origin": ida_nalt.get_input_file_path(), "regions": regions,
            "functions": list(unique.values()), "references": references}


def snapshot():
    """Export current IDA memory and metadata on its main thread."""
    return _main(_snapshot)


def _write(path, value):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".armflow-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class DatabaseJob:
    """Explicit host session; native stages do not directly modify the database."""

    def __init__(self, executable, configuration):
        self.executable = str(Path(executable).resolve(strict=True))
        self.configuration = copy.deepcopy(configuration)
        # File resolution belongs to the CLI. An embedded session requires an
        # already materialized config, making cwd-independent receipts possible.
        if "image" in self.configuration or "trace_files" in self.configuration:
            raise BridgeError("embedded configuration requires inline image-independent settings and observations")
        self.original = snapshot()
        self.last_receipt = None

    def _native(self, command, apply=False, receipt=None):
        with tempfile.ScratchDirectory(prefix="armflow-ida-") as directory:
            root = Path(directory)
            _write(root / "source.json", self.original)
            _write(root / "config.json", self.configuration)
            argv = [self.executable, command, "--image", str(root / "source.json"),
                    "--config", str(root / "config.json"), "--output", str(root / "result.json")]
            if apply:
                argv.append("--apply")
            if receipt is not None:
                _write(root / "receipt.json", receipt)
                argv.extend(["--from", str(root / "receipt.json")])
            # Files avoid unbounded output accumulation. Native command execution
            # has its own independent deadlines and bounded response protocol.
            with open(root / "stdout.log", "wb") as stdout, open(root / "stderr.log", "wb") as stderr:
                try:
                    process = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=600, check=False)
                except subprocess.TimeoutExpired as error:
                    raise BridgeError("native workflow timed out; database unchanged") from error
            if process.returncode:
                detail = (root / "stderr.log").read_bytes()[:8192].decode("utf-8", errors="replace")
                raise BridgeError(f"native workflow failed ({process.returncode}): {detail}")
            if (root / "result.json").stat().st_size > 768 * 1024 * 1024:
                raise BridgeError("native result exceeds bridge limit")
            result = json.loads((root / "result.json").read_text(encoding="utf-8"))
            if "image" in result:
                # The CLI records its temporary snapshot path as origin. Origin
                # is informational and excluded from the native fingerprint.
                result["image"]["origin"] = self.original["origin"]
            return result

    def preview(self, command="preview"):
        return self._native(command)

    def apply(self, command="run"):
        if command not in ("run", "graph", "cleanup"):
            raise BridgeError("only run, graph and cleanup may apply host changes")
        receipt = self._native(command, apply=True)
        # Idempotence still regenerates and verifies the native result.
        if self.last_receipt and snapshot() == self.last_receipt["after"]:
            if receipt != self.last_receipt["native"]:
                raise BridgeError("repeated native result differs from the applied transaction")
            return copy.deepcopy(self.last_receipt)

        def submit():
            if _snapshot() != self.original:
                raise BridgeError("database changed since capture; no host changes applied")
            edits = receipt["plan"]["edits"]
            for edit in edits:
                address = int(edit["address"], 16)
                if ida_bytes.get_bytes(address, 4) != bytes.fromhex(edit["expected"]):
                    raise BridgeError("host instruction differs from verified source")
            added, patched = [], []
            auto_enabled = ida_auto.enable_auto(False)
            try:
                for edit in edits:
                    address = int(edit["address"], 16)
                    # Log before the call, including a host failure after writing.
                    patched.append(edit)
                    ida_bytes.patch_bytes(address, bytes.fromhex(edit["replacement"]))
                    if ida_bytes.get_bytes(address, 4) != bytes.fromhex(edit["replacement"]):
                        raise BridgeError("IDA failed to write the verified instruction")
                for edge in receipt["plan"]["graph"]:
                    source, target = int(edge["source"], 16), int(edge["target"], 16)
                    if _has_reference(source, target):
                        continue
                    added.append(edge)
                    if not ida_xref.add_cref(source, target, ida_xref.fl_JN | ida_xref.XREF_USER):
                        raise BridgeError("IDA refused a graph reference")
                    if not _has_reference(source, target):
                        raise BridgeError("IDA did not retain a graph reference")
                after = _snapshot()
            except BaseException as error:
                recovery_errors = []
                for edge in reversed(added):
                    source, target = int(edge["source"], 16), int(edge["target"], 16)
                    ida_xref.del_cref(source, target, False)
                    if _has_reference(source, target):
                        recovery_errors.append("graph rollback failed")
                for edit in reversed(patched):
                    address = int(edit["address"], 16)
                    ida_bytes.patch_bytes(address, bytes.fromhex(edit["expected"]))
                    if ida_bytes.get_bytes(address, 4) != bytes.fromhex(edit["expected"]):
                        recovery_errors.append("byte rollback failed")
                if recovery_errors or _snapshot() != self.original:
                    raise BridgeError("host failure with incomplete rollback: " + "; ".join(recovery_errors)) from error
                raise BridgeError("host transaction failed and was rolled back: " + str(error)) from error
            finally:
                ida_auto.enable_auto(auto_enabled)
            ida_kernwin.refresh_idaview_anyway()
            return {"bridge_version": 1, "native": receipt, "before": self.original,
                    "after": after, "host_added_edges": added, "applied": True}

        self.last_receipt = _main(submit, write=True)
        return copy.deepcopy(self.last_receipt)

    def restore(self, receipt=None):
        receipt = copy.deepcopy(receipt if receipt is not None else self.last_receipt)
        if not receipt or receipt.get("bridge_version") != 1 or not receipt.get("applied"):
            raise BridgeError("restore requires an applied host receipt")
        if receipt["before"] != self.original:
            raise BridgeError("host receipt belongs to a different source snapshot")
        # Native code regenerates the plan and graph ownership from the source.
        self._native("restore", receipt=receipt["native"])
        expected_edges = {(int(edge["source"], 16), int(edge["target"], 16))
                          for edge in receipt["native"]["plan"]["graph"]}
        before_edges = {(int(edge["source"], 16), int(edge["target"], 16))
                        for edge in receipt["before"]["references"]}
        logged = [(int(edge["source"], 16), int(edge["target"], 16)) for edge in receipt["host_added_edges"]]
        if len(logged) != len(set(logged)) or any(edge not in expected_edges or edge in before_edges for edge in logged):
            raise BridgeError("host ownership log contains a foreign or pre-existing edge")
        # Do not accept a forged 'after' snapshot: reconstruct its bytes and user
        # reference set from before plus the native plan and actual host log.
        expected_after = copy.deepcopy(self.original)
        for edit in receipt["native"]["plan"]["edits"]:
            address = int(edit["address"], 16)
            for region in expected_after["regions"]:
                start = int(region["begin"], 16)
                data = bytearray.fromhex(region["bytes"])
                if start <= address and address + 4 <= start + len(data):
                    data[address-start:address-start+4] = bytes.fromhex(edit["replacement"])
                    region["bytes"] = data.hex()
                    break
            else:
                raise BridgeError("native edit lies outside exported memory")
        for source, target in logged:
            expected_after["references"].append({"source": hex(source), "target": hex(target), "owned": False})
        expected_after["references"].sort(key=lambda edge: (int(edge["source"], 16), int(edge["target"], 16)))
        if expected_after != receipt["after"]:
            raise BridgeError("host receipt bytes or reference ownership were changed")

        def undo():
            current = _snapshot()
            if current == self.original:
                return {"restored": True, "already_restored": True}
            if current != receipt["after"]:
                raise BridgeError("database has unrelated changes; restore refused")
            auto_enabled = ida_auto.enable_auto(False)
            removed, patched = [], []
            try:
                for source, target in logged:
                    removed.append((source, target))
                    ida_xref.del_cref(source, target, False)
                    if _has_reference(source, target):
                        raise BridgeError("IDA failed to remove an owned reference")
                for edit in receipt["native"]["plan"]["edits"]:
                    patched.append(edit)
                    address = int(edit["address"], 16)
                    ida_bytes.patch_bytes(address, bytes.fromhex(edit["expected"]))
                    if ida_bytes.get_bytes(address, 4) != bytes.fromhex(edit["expected"]):
                        raise BridgeError("IDA failed to restore an instruction")
                if _snapshot() != self.original:
                    raise BridgeError("restored host snapshot differs from original")
            except BaseException as error:
                for edit in patched:
                    ida_bytes.patch_bytes(int(edit["address"], 16), bytes.fromhex(edit["replacement"]))
                for source, target in removed:
                    ida_xref.add_cref(source, target, ida_xref.fl_JN | ida_xref.XREF_USER)
                if _snapshot() != receipt["after"]:
                    raise BridgeError("restore failed and rollback was incomplete") from error
                raise BridgeError("restore failed; applied host state was recovered") from error
            finally:
                ida_auto.enable_auto(auto_enabled)
            ida_kernwin.refresh_idaview_anyway()
            return {"restored": True, "removed_edges": len(logged), "restored_instructions": len(patched)}
        return _main(undo, write=True)

    def save_receipt(self, path):
        if not self.last_receipt:
            raise BridgeError("no applied host transaction to save")
        _write(path, {"configuration": self.configuration, "receipt": self.last_receipt})

    @classmethod
    def resume(cls, executable, path):
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        job = cls.__new__(cls)
        job.executable = str(Path(executable).resolve(strict=True))
        job.configuration = data["configuration"]
        job.last_receipt = data["receipt"]
        job.original = job.last_receipt["before"]
        return job
