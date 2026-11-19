#!/usr/bin/env python3
"""Regression checks for offline trace-PC remapping."""

from pathlib import Path
import struct
import subprocess
import sys
import tempfile


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = REPO_ROOT / "scripts" / "tracertl"
sys.path.insert(0, str(SCRIPT_DIR))
import remap_trace_pcs as remap

REMAP = SCRIPT_DIR / "remap_trace_pcs.py"
TRACE_REC = struct.Struct("<QQQQQIBBBB")
PHASE1_BASE = remap.PHASE1_BASE


def pack_record(*, pc, instr=0x00100093, target=0, branch_type=0, branch_taken=0,
                mem_va=0, mem_pa=0, memory_type=0, memory_size=0,
                exception=0) -> bytes:
    return TRACE_REC.pack(
        pc,
        pc,
        mem_va,
        mem_pa,
        target,
        instr,
        memory_type | (memory_size << 4),
        branch_type,
        branch_taken,
        exception,
    )


def parse_records(raw):
    if len(raw) % TRACE_REC.size != 0:
        raise AssertionError(f"raw trace size {len(raw)} is not a multiple of {TRACE_REC.size}")

    records = []
    for off in range(0, len(raw), TRACE_REC.size):
        pc, pc_pa, payload0, payload1, target, instr, mts, branch_type, branch_taken, exception = (
            TRACE_REC.unpack_from(raw, off)
        )
        records.append({
            "pc": pc,
            "pc_pa": pc_pa,
            "payload0": payload0,
            "payload1": payload1,
            "target": target,
            "instr": instr,
            "memory_type": mts & 0x0F,
            "memory_size": (mts >> 4) & 0x0F,
            "branch_type": branch_type,
            "branch_taken": branch_taken,
            "exception": exception,
        })
    return records


def pc_target_stream(records):
    return [(rec["pc"], rec["target"]) for rec in records]


def sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def branch_target(pc: int, instr: int) -> int:
    imm = (
        ((instr >> 31) & 0x1) << 12
        | ((instr >> 7) & 0x1) << 11
        | ((instr >> 25) & 0x3F) << 5
        | ((instr >> 8) & 0xF) << 1
    )
    return pc + sign_extend(imm, 13)


def jal_target(pc: int, instr: int) -> int:
    imm = (
        ((instr >> 31) & 0x1) << 20
        | ((instr >> 12) & 0xFF) << 12
        | ((instr >> 20) & 0x1) << 11
        | ((instr >> 21) & 0x3FF) << 1
    )
    return pc + sign_extend(imm, 21)


def write_trace(path: Path, records) -> Path:
    raw_path = path.with_suffix("")
    with raw_path.open("wb") as f:
        for rec in records:
            f.write(pack_record(**rec))
    subprocess.run(["zstd", "-q", "-f", str(raw_path), "-o", str(path)], check=True)
    return path


def decompress(path: Path) -> bytes:
    return subprocess.check_output(["zstd", "-q", "-d", "-c", str(path)])


def write_sidecar(path: Path, intervals, *, mode=None) -> None:
    with path.open("w", encoding="ascii") as f:
        f.write("# trace_pc_start,trace_pc_end,tag\n")
        if mode is not None:
            f.write(f"# sidecar_mode={mode}\n")
        for start, end, tag in intervals:
            f.write(f"0x{start:x},0x{end:x},{tag}\n")


def write_binary_sidecar(path: Path, intervals) -> None:
    tag_to_id = {name: value for value, name in remap.SIDECAR_BIN_TAGS.items()}
    payload = bytearray()
    for start, end, tag in intervals:
        payload.extend(remap.SIDECAR_BIN_ENTRY.pack(start, end, tag_to_id[tag], 0))
    path.write_bytes(
        remap.SIDECAR_BIN_HEADER.pack(
            remap.SIDECAR_BIN_MAGIC, 1, remap.SIDECAR_BIN_MODE_ORDINAL, 0
        )
        + payload
    )


def read_sidecar(path: Path):
    with path.open("r", encoding="ascii") as f:
        lines = [line.strip() for line in f if line.strip()]
    return lines


def run_remap(src: Path, dst: Path):
    return subprocess.run(
        [sys.executable, str(REMAP), str(src), str(dst)],
        text=True,
        capture_output=True,
        check=False,
    )


def assert_whole_trace_next_pc(records) -> None:
    for index in range(1, len(records)):
        prev = records[index - 1]
        cur = records[index]
        if (prev["branch_taken"] != 0 or prev["exception"] != 0) and prev["target"] != 0:
            expected = prev["target"]
        else:
            expected = prev["pc"] + 4
        if cur["pc"] != expected:
            raise AssertionError(
                f"record {index - 1}->{index} expected pc 0x{expected:x}, got 0x{cur['pc']:x}"
            )


def test_small_gaps_pack_dense_and_split_duplicates(tmp: Path) -> None:
    src = write_trace(
        tmp / "small-gap.trace.zst",
        [
            {"pc": 0x1000},
            {"pc": 0x1010},
            {"pc": 0x1010},
        ],
    )
    dst = tmp / "small-gap.remap.trace.zst"

    result = run_remap(src, dst)
    if result.returncode != 0:
        raise AssertionError(
            "remap_trace_pcs.py failed for small-gap packing test:\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    records = parse_records(decompress(dst))
    pcs = [rec["pc"] for rec in records]
    expected_pcs = [PHASE1_BASE, PHASE1_BASE + 4, PHASE1_BASE + 8]
    if pcs != expected_pcs:
        raise AssertionError(f"expected dense packed PCs {expected_pcs!r}, got {pcs!r}")

    write_sidecar(
        Path(f"{src}.pc-tags.csv"),
        [(0x1010, 0x1014, "movcond")],
        mode="raw-pc",
    )
    result = run_remap(src, dst)
    if result.returncode != 0:
        raise AssertionError(
            "remap_trace_pcs.py failed while rewriting sidecar data:\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    sidecar_lines = read_sidecar(Path(f"{dst}.pc-tags.csv"))
    expected = [
        "# trace_pc_start,trace_pc_end,tag",
        f"0x{PHASE1_BASE + 4:x},0x{PHASE1_BASE + 12:x},movcond",
    ]
    if sidecar_lines != expected:
        raise AssertionError(f"expected rewritten sidecar {expected!r}, got {sidecar_lines!r}")


def test_large_gaps_are_preserved_and_targets_follow_split_map(tmp: Path) -> None:
    src = write_trace(
        tmp / "large-gap.trace.zst",
        [
            {"pc": 0x2000},
            {"pc": 0x2000},
            {"pc": 0x2100, "instr": 0x0080006F, "target": 0x3000,
             "branch_type": 2, "branch_taken": 1},
            {"pc": 0x3000},
            {"pc": 0x3000},
        ],
    )
    dst = tmp / "large-gap.remap.trace.zst"

    result = run_remap(src, dst)
    if result.returncode != 0:
        raise AssertionError(
            "remap_trace_pcs.py failed for large-gap target test:\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    records = parse_records(decompress(dst))
    pcs = [rec["pc"] for rec in records]
    expected_pcs = [
        PHASE1_BASE,
        PHASE1_BASE + 4,
        PHASE1_BASE + 0x100,
        PHASE1_BASE + 0x1000,
        PHASE1_BASE + 0x1004,
    ]
    if pcs != expected_pcs:
        raise AssertionError(f"expected preserved large-gap PCs, got {pcs!r}")

    expected_target = PHASE1_BASE + 0x1000
    if records[2]["target"] != expected_target:
        raise AssertionError(
            f"expected branch target 0x{expected_target:x} after remap, got 0x{records[2]['target']:x}"
        )
    if (records[2]["instr"] & 0x7F) != 0x6F:
        raise AssertionError(
            f"expected out-of-B-range direct jump to stay a JAL-shaped placeholder, "
            f"got instr=0x{records[2]['instr']:08x}"
        )
    if jal_target(records[2]["pc"], records[2]["instr"]) != records[2]["target"]:
        raise AssertionError(
            "expected remapped JAL placeholder immediate to agree with target metadata"
        )


def test_taken_conditional_branch_fallback_metadata_matches_jal_opcode(tmp: Path) -> None:
    src = write_trace(
        tmp / "cond-large-gap.trace.zst",
        [
            {"pc": 0x2000},
            {"pc": 0x2000},
            {"pc": 0x2100, "instr": 0x00000063, "target": 0x5000,
             "branch_type": 1, "branch_taken": 1},
            {"pc": 0x5000},
            {"pc": 0x5000},
        ],
    )
    dst = tmp / "cond-large-gap.remap.trace.zst"

    result = run_remap(src, dst)
    if result.returncode != 0:
        raise AssertionError(
            "remap_trace_pcs.py failed for conditional branch JAL fallback test:\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    records = parse_records(decompress(dst))
    pcs = [rec["pc"] for rec in records]
    expected_pcs = [
        PHASE1_BASE,
        PHASE1_BASE + 4,
        PHASE1_BASE + 0x100,
        PHASE1_BASE + 0x3000,
        PHASE1_BASE + 0x3004,
    ]
    if pcs != expected_pcs:
        raise AssertionError(
            f"expected large-gap layout to remain stable, got {pcs!r}"
        )

    expected_target = PHASE1_BASE + 0x3000
    if records[2]["target"] != expected_target:
        raise AssertionError(
            f"expected branch target 0x{expected_target:x} after remap, got 0x{records[2]['target']:x}"
        )
    if (records[2]["instr"] & 0x7F) != 0x6F:
        raise AssertionError(
            f"expected out-of-B-range conditional branch to use a JAL-shaped fallback, "
            f"got instr=0x{records[2]['instr']:08x}"
        )
    if records[2]["branch_type"] != 2:
        raise AssertionError(
            f"expected JAL fallback metadata branch_type=2, got {records[2]['branch_type']}"
        )
    if jal_target(records[2]["pc"], records[2]["instr"]) != records[2]["target"]:
        raise AssertionError(
            "expected remapped JAL fallback immediate to agree with target metadata"
        )


def test_branch_immediate_rewritten_after_pc_remap(tmp: Path) -> None:
    src = write_trace(
        tmp / "branch-immediate.trace.zst",
        [
            {"pc": 0x1000},
            {"pc": 0x1004, "instr": 0x00000063, "target": 0x1100,
             "branch_type": 1, "branch_taken": 1},
            {"pc": 0x1100},
        ],
    )
    dst = tmp / "branch-immediate.remap.trace.zst"

    result = run_remap(src, dst)
    if result.returncode != 0:
        raise AssertionError(
            "remap_trace_pcs.py failed for branch-immediate rewrite test:\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    records = parse_records(decompress(dst))
    branch = records[1]
    if (branch["instr"] & 0x7F) != 0x63:
        raise AssertionError(f"expected B-type branch placeholder, got 0x{branch['instr']:08x}")
    if branch_target(branch["pc"], branch["instr"]) != branch["target"]:
        raise AssertionError(
            f"expected encoded branch target 0x{branch_target(branch['pc'], branch['instr']):x} "
            f"to match metadata target 0x{branch['target']:x}"
        )


def test_taken_sequential_cfi_preserves_branch(tmp: Path) -> None:
    src = write_trace(
        tmp / "sequential-cfi.trace.zst",
        [
            {"pc": 0x1000},
            {"pc": 0x1004, "instr": 0x0000006F, "target": 0x1008,
             "branch_type": 2, "branch_taken": 1},
            {"pc": 0x1008},
        ],
    )
    dst = tmp / "sequential-cfi.remap.trace.zst"

    result = run_remap(src, dst)
    if result.returncode != 0:
        raise AssertionError(
            "remap_trace_pcs.py failed for sequential CFI demotion test:\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    records = parse_records(decompress(dst))
    rec = records[1]
    if rec["branch_type"] != 2 or rec["branch_taken"] != 1:
        raise AssertionError(f"remapping erased a taken branch: {rec!r}")
    if rec["target"] != records[2]["pc"] or jal_target(rec["pc"],rec["instr"]) != rec["target"]:
        raise AssertionError(f"remapped adjacent JAL has inconsistent target: {rec!r}")
    assert_whole_trace_next_pc(records)


def test_rejects_non_record_aligned_payload(tmp: Path) -> None:
    raw = tmp / "bad.trace"
    src = tmp / "bad.trace.zst"
    dst = tmp / "bad.remap.trace.zst"

    raw.write_bytes(b"x" * (TRACE_REC.size - 1))
    subprocess.run(["zstd", "-q", "-f", str(raw), "-o", str(src)], check=True)

    result = run_remap(src, dst)
    if result.returncode == 0:
        raise AssertionError("expected remap_trace_pcs.py to reject a payload whose size is not a multiple of 48")

    combined = (result.stdout + "\n" + result.stderr).lower()
    if "multiple of 48" not in combined and "48" not in combined:
        raise AssertionError(
            "expected an error mentioning the 48-byte record contract, got:\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )


def test_exception_terminated_split_run_keeps_unique_pcs_and_target(tmp: Path) -> None:
    src = write_trace(
        tmp / "exception-split.trace.zst",
        [
            {"pc": 0x2000},
            {"pc": 0x2000},
            {"pc": 0x2000, "instr": 0x00000073, "exception": 1, "target": 0x2100},
        ],
    )
    dst = tmp / "exception-split.remap.trace.zst"

    result = run_remap(src, dst)
    if result.returncode != 0:
        raise AssertionError(
            "remap_trace_pcs.py failed for exception-terminated split test:\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    records = parse_records(decompress(dst))
    pcs = [rec["pc"] for rec in records]
    expected_pcs = [PHASE1_BASE, PHASE1_BASE + 4, PHASE1_BASE + 8]
    if pcs != expected_pcs:
        raise AssertionError(f"expected exception split run to expand to unique PCs, got {pcs!r}")

    expected_target = PHASE1_BASE + 0x48
    if records[-1]["target"] != expected_target:
        raise AssertionError(
            f"expected exception redirect target 0x{expected_target:x} to stay non-zero after remap, got 0x{records[-1]['target']:x}"
        )


def test_variable_split_lengths_do_not_leave_straight_line_holes(tmp: Path) -> None:
    src = write_trace(
        tmp / "variable-split.trace.zst",
        [
            {"pc": 0x1000},
            {"pc": 0x1000},
            {"pc": 0x1004},
            {"pc": 0x1004},
            {"pc": 0x1004},
            {"pc": 0x1004},
            {"pc": 0x1008, "instr": 0x0080006F, "target": 0x1004,
             "branch_type": 2, "branch_taken": 1},
            {"pc": 0x1004},
            {"pc": 0x1004},
            {"pc": 0x1004},
            {"pc": 0x1004},
            {"pc": 0x1004},
            {"pc": 0x1004},
            {"pc": 0x1004},
        ],
    )
    dst = tmp / "variable-split.remap.trace.zst"

    result = run_remap(src, dst)
    if result.returncode != 0:
        raise AssertionError(
            "remap_trace_pcs.py failed for variable split-length continuity test:\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    records = parse_records(decompress(dst))
    assert_whole_trace_next_pc(records)

    pcs = [rec["pc"] for rec in records]
    expected = [
        PHASE1_BASE + 0x0, PHASE1_BASE + 0x4, PHASE1_BASE + 0x8,
        PHASE1_BASE + 0xC, PHASE1_BASE + 0x10, PHASE1_BASE + 0x14,
        PHASE1_BASE + 0x18, PHASE1_BASE + 0x1C, PHASE1_BASE + 0x20,
        PHASE1_BASE + 0x24, PHASE1_BASE + 0x28, PHASE1_BASE + 0x2C,
        PHASE1_BASE + 0x30, PHASE1_BASE + 0x34,
    ]
    if pcs != expected:
        raise AssertionError(f"expected contiguous remap without holes, got {pcs!r}")

    branch = records[6]
    if branch["branch_type"] != 2 or branch["branch_taken"] != 1:
        raise AssertionError(f"packing erased the source backedge: {branch!r}")
    if branch["target"] != records[7]["pc"] or jal_target(branch["pc"], branch["instr"]) != branch["target"]:
        raise AssertionError(f"packed backedge target does not match its successor: {branch!r}")


def test_loop_backedges_reuse_canonical_taken_target_block(tmp: Path) -> None:
    src = write_trace(
        tmp / "loop-backedge.trace.zst",
        [
            {"pc": 0x1004, "instr": 0x00008093},
            {"pc": 0x1004, "instr": 0xFFF48293},
            {"pc": 0x1004, "instr": 0x02049293},
            {"pc": 0x1004, "instr": 0x0202D293},
            {"pc": 0x1008, "instr": 0x00008093},
            {"pc": 0x1008, "instr": 0x0124F0B3},
            {"pc": 0x1008, "instr": 0x00009063, "target": 0x1004,
             "branch_type": 1, "branch_taken": 1},
            {"pc": 0x1004, "instr": 0x00008093},
            {"pc": 0x1004, "instr": 0xFFF48293},
            {"pc": 0x1004, "instr": 0x02049293},
            {"pc": 0x1004, "instr": 0x0202D293},
            {"pc": 0x1008, "instr": 0x00008093},
            {"pc": 0x1008, "instr": 0x0124F0B3},
            {"pc": 0x1008, "instr": 0x00009063, "target": 0x1004,
             "branch_type": 1, "branch_taken": 0},
        ],
    )
    dst = tmp / "loop-backedge.remap.trace.zst"

    result = run_remap(src, dst)
    if result.returncode != 0:
        raise AssertionError(
            "remap_trace_pcs.py failed for loop backedge reuse test:\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    records = parse_records(decompress(dst))
    assert_whole_trace_next_pc(records)

    if records[6]["target"] >= records[6]["pc"]:
        raise AssertionError(
            f"expected loop backedge target to reuse an earlier block base, got "
            f"pc=0x{records[6]['pc']:x} target=0x{records[6]['target']:x}"
        )


def test_sidecar_drops_ambiguous_final_pcs_after_block_reuse(tmp: Path) -> None:
    src = write_trace(
        tmp / "sidecar-conflict.trace.zst",
        [
            {"pc": 0x1000, "instr": 0x00100093},
            {"pc": 0x1004, "instr": 0x0080006F, "target": 0x1000,
             "branch_type": 2, "branch_taken": 1},
            {"pc": 0x1000, "instr": 0x00200093},
            {"pc": 0x1004, "instr": 0x0080006F, "target": 0x1000,
             "branch_type": 2, "branch_taken": 1},
        ],
    )
    dst = tmp / "sidecar-conflict.remap.trace.zst"
    write_sidecar(
        Path(f"{src}.pc-tags.csv"),
        [
            (0x0, 0x4, "movcond"),
            (0x4, 0x8, "indirect_branch_placeholder"),
            (0x8, 0xC, "helper_placeholder"),
            (0xC, 0x10, "indirect_branch_placeholder"),
        ],
        mode="ordinal",
    )

    result = run_remap(src, dst)
    if result.returncode != 0:
        raise AssertionError(
            "remap_trace_pcs.py failed for sidecar conflict rewrite test:\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    sidecar_lines = read_sidecar(Path(f"{dst}.pc-tags.csv"))
    expected = [
        "# trace_pc_start,trace_pc_end,tag",
        f"0x{PHASE1_BASE + 4:x},0x{PHASE1_BASE + 8:x},indirect_branch_placeholder",
    ]
    if sidecar_lines != expected:
        raise AssertionError(
            f"expected ambiguous final PCs to be dropped from the sidecar, got {sidecar_lines!r}"
        )


def test_low_address_raw_pc_sidecar_requires_explicit_mode(tmp: Path) -> None:
    src = write_trace(
        tmp / "low-address-raw-pc.trace.zst",
        [
            {"pc": 0x4},
            {"pc": 0x8},
            {"pc": 0x8},
        ],
    )
    dst = tmp / "low-address-raw-pc.remap.trace.zst"
    write_sidecar(
        Path(f"{src}.pc-tags.csv"),
        [(0x8, 0xC, "movcond")],
    )

    result = run_remap(src, dst)
    if result.returncode == 0:
        raise AssertionError("expected low-address sidecar without explicit mode to be rejected")

    combined = result.stdout + "\n" + result.stderr
    if "ambiguous low-address sidecar without explicit mode" not in combined:
        raise AssertionError(
            "expected low-address sidecar failure to request an explicit mode, got:\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )


def test_explicit_raw_pc_sidecar_mode_handles_low_address_trace(tmp: Path) -> None:
    src = write_trace(
        tmp / "low-address-raw-pc-explicit.trace.zst",
        [
            {"pc": 0x4},
            {"pc": 0x8},
            {"pc": 0x8},
        ],
    )
    dst = tmp / "low-address-raw-pc-explicit.remap.trace.zst"
    write_sidecar(
        Path(f"{src}.pc-tags.csv"),
        [(0x8, 0xC, "movcond")],
        mode="raw-pc",
    )

    result = run_remap(src, dst)
    if result.returncode != 0:
        raise AssertionError(
            "remap_trace_pcs.py failed for explicit low-address raw-pc sidecar test:\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    sidecar_lines = read_sidecar(Path(f"{dst}.pc-tags.csv"))
    expected = [
        "# trace_pc_start,trace_pc_end,tag",
        f"0x{PHASE1_BASE + 4:x},0x{PHASE1_BASE + 12:x},movcond",
    ]
    if sidecar_lines != expected:
        raise AssertionError(
            f"expected explicit raw-pc sidecar to tag the remapped duplicated guest site, got {sidecar_lines!r}"
        )


def test_constant_address_offset_remaps_to_identical_pc_target_stream(tmp: Path) -> None:
    template = [
        {"pc": 0x2000},
        {"pc": 0x2000},
        {"pc": 0x2100, "instr": 0x0080006F, "target": 0x3000,
         "branch_type": 2, "branch_taken": 1},
        {"pc": 0x3000},
        {"pc": 0x3000},
    ]

    def offset_records(delta):
        records = []
        for rec in template:
            shifted = dict(rec)
            shifted["pc"] = rec["pc"] + delta
            if rec.get("target", 0) != 0:
                shifted["target"] = rec["target"] + delta
            records.append(shifted)
        return records

    src_a = write_trace(tmp / "offset-a.trace.zst", offset_records(0))
    src_b = write_trace(tmp / "offset-b.trace.zst", offset_records(0x400000))
    dst_a = tmp / "offset-a.remap.trace.zst"
    dst_b = tmp / "offset-b.remap.trace.zst"

    result_a = run_remap(src_a, dst_a)
    result_b = run_remap(src_b, dst_b)
    if result_a.returncode != 0 or result_b.returncode != 0:
        raise AssertionError(
            "remap_trace_pcs.py failed for constant-offset determinism test:\n"
            f"stdout-a:\n{result_a.stdout}\nstderr-a:\n{result_a.stderr}\n"
            f"stdout-b:\n{result_b.stdout}\nstderr-b:\n{result_b.stderr}"
        )

    records_a = parse_records(decompress(dst_a))
    records_b = parse_records(decompress(dst_b))
    if pc_target_stream(records_a) != pc_target_stream(records_b):
        raise AssertionError(
            "expected constant raw-PC offsets to produce identical remapped (pc,target) streams"
        )


def test_remap_keeps_pc_pa_aligned_with_synthetic_pc(tmp: Path) -> None:
    src = write_trace(
        tmp / "pc-pa-align.trace.zst",
        [
            {"pc": 0x1000},
            {"pc": 0x1000},
            {"pc": 0x1100, "instr": 0x0080006F, "target": 0x1000,
             "branch_type": 2, "branch_taken": 1},
            {"pc": 0x1000},
        ],
    )
    dst = tmp / "pc-pa-align.remap.trace.zst"

    result = run_remap(src, dst)
    if result.returncode != 0:
        raise AssertionError(
            "remap_trace_pcs.py failed for pc/pa alignment test:\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    records = parse_records(decompress(dst))
    for index, rec in enumerate(records):
        if rec["pc_pa"] != rec["pc"]:
            raise AssertionError(
                f"expected remapped record {index} to keep pc_pa aligned with pc, "
                f"got pc=0x{rec['pc']:x} pc_pa=0x{rec['pc_pa']:x}"
            )


def test_raw_trace_input_remaps_and_compresses(tmp: Path) -> None:
    src = tmp / "raw-input.trace.raw"
    src.write_bytes(pack_record(pc=0x1000) + pack_record(pc=0x1004))
    dst = tmp / "raw-input.remap.trace.zst"

    result = run_remap(src, dst)
    if result.returncode != 0:
        raise AssertionError(
            "remap_trace_pcs.py failed for raw trace input:\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    records = parse_records(decompress(dst))
    if [rec["pc"] for rec in records] != [PHASE1_BASE, PHASE1_BASE + 4]:
        raise AssertionError(f"unexpected raw-input remap PCs: {[rec['pc'] for rec in records]!r}")


def test_binary_sidecar_read_and_remap(tmp: Path) -> None:
    src = write_trace(
        tmp / "binary-sidecar.trace.zst",
        [
            {"pc": 0x1000},
            {"pc": 0x1010},
        ],
    )
    dst = tmp / "binary-sidecar.remap.trace.zst"
    sidecar = Path(f"{src}.pc-tags.bin")
    write_binary_sidecar(sidecar, [(0, 4, "movcond")])

    mode, entries = remap.read_sidecar(sidecar)
    if mode != "ordinal" or entries != [(0, 4, "movcond")]:
        raise AssertionError(f"unexpected binary sidecar decode: {mode!r} {entries!r}")

    result = run_remap(src, dst)
    if result.returncode != 0:
        raise AssertionError(
            "remap_trace_pcs.py failed for binary sidecar test:\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    sidecar_lines = read_sidecar(Path(f"{dst}.pc-tags.csv"))
    expected = [
        "# trace_pc_start,trace_pc_end,tag",
        f"0x{PHASE1_BASE:x},0x{PHASE1_BASE + 4:x},movcond",
    ]
    if sidecar_lines != expected:
        raise AssertionError(f"expected binary sidecar remap {expected!r}, got {sidecar_lines!r}")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="remap-trace-pcs-regressions-") as tmpdir:
        tmp = Path(tmpdir)
        test_small_gaps_pack_dense_and_split_duplicates(tmp)
        test_large_gaps_are_preserved_and_targets_follow_split_map(tmp)
        test_taken_conditional_branch_fallback_metadata_matches_jal_opcode(tmp)
        test_branch_immediate_rewritten_after_pc_remap(tmp)
        test_taken_sequential_cfi_preserves_branch(tmp)
        test_rejects_non_record_aligned_payload(tmp)
        test_exception_terminated_split_run_keeps_unique_pcs_and_target(tmp)
        test_variable_split_lengths_do_not_leave_straight_line_holes(tmp)
        test_loop_backedges_reuse_canonical_taken_target_block(tmp)
        test_sidecar_drops_ambiguous_final_pcs_after_block_reuse(tmp)
        test_low_address_raw_pc_sidecar_requires_explicit_mode(tmp)
        test_explicit_raw_pc_sidecar_mode_handles_low_address_trace(tmp)
        test_constant_address_offset_remaps_to_identical_pc_target_stream(tmp)
        test_remap_keeps_pc_pa_aligned_with_synthetic_pc(tmp)
        test_raw_trace_input_remaps_and_compresses(tmp)
        test_binary_sidecar_read_and_remap(tmp)

    print("PASS: offline trace-PC remap packs small gaps, preserves large gaps, updates split-aware targets, rejects malformed payloads, and requires explicit sidecar mode for ambiguous low-address traces")
    return 0


if __name__ == "__main__":
    sys.exit(main())
