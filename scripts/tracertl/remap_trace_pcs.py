#!/usr/bin/env python3
"""Offline synthetic-PC remap for TracerTL traces."""

from __future__ import annotations

import argparse
import io
from pathlib import Path
import struct
import subprocess
import sys
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


TRACE_REC = struct.Struct("<QQQQQIBBBB")
SIDECAR_BIN_MAGIC = b"TRPCTAG1"
SIDECAR_BIN_HEADER = struct.Struct("<8sIII")
SIDECAR_BIN_ENTRY = struct.Struct("<QQII")
SIDECAR_BIN_MODE_ORDINAL = 1
SIDECAR_BIN_TAGS = {
    1: "movcond",
    2: "helper_placeholder",
    3: "indirect_branch_placeholder",
    4: "generic_dependency_placeholder",
}
RECORD_SIZE = TRACE_REC.size
BIG_JUMP = 64
INST_SIZE = 4
PHASE1_BASE = 0x400000000000
OP_BRANCH = 0x63
OP_JAL = 0x6F
OP_JALR = 0x67
NON_BRANCH_PLACEHOLDER = 0x01E080B3


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Remap raw guest PCs in a TracerTL trace into deterministic synthetic PCs"
    )
    parser.add_argument("input", help="Input .trace.zst/.zstd path")
    parser.add_argument("output", help="Output trace path (may be the same as input)")
    return parser.parse_args()


def decompress_trace(path: Path) -> bytes:
    if not path.exists():
        raise RuntimeError(f"input trace not found: {path}")
    if path.stat().st_size == 0:
        raise RuntimeError(f"input trace is empty: {path}")

    with path.open("rb") as f:
        magic = f.read(4)
    if magic != b"\x28\xb5\x2f\xfd":
        return path.read_bytes()

    try:
        import zstandard as zstd  # type: ignore

        dctx = zstd.ZstdDecompressor()
        with path.open("rb") as f:
            if hasattr(dctx, "stream_reader"):
                reader = dctx.stream_reader(f)
                try:
                    raw = bytearray()
                    while True:
                        chunk = reader.read(1024 * 1024)
                        if not chunk:
                            break
                        raw.extend(chunk)
                finally:
                    reader.close()
                return bytes(raw)

            out = io.BytesIO()
            dctx.copy_stream(f, out)
            return out.getvalue()
    except ImportError:
        pass
    except Exception as exc:
        raise RuntimeError(f"zstandard decompression failed: {exc}") from exc

    try:
        return subprocess.check_output(["zstd", "-q", "-d", "-c", str(path)])
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode(errors="replace") if exc.stderr else ""
        raise RuntimeError(f"zstd failed for {path}: {stderr or exc}") from exc


def compress_trace(raw: bytes, path: Path) -> None:
    tmp_raw = path.with_suffix(path.suffix + ".raw")
    tmp_raw.write_bytes(raw)

    try:
        try:
            import zstandard as zstd  # type: ignore

            cctx = zstd.ZstdCompressor()
            with tmp_raw.open("rb") as src, path.open("wb") as dst:
                cctx.copy_stream(src, dst)
            return
        except ImportError:
            pass

        subprocess.run(
            ["zstd", "-q", "-f", str(tmp_raw), "-o", str(path)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    finally:
        tmp_raw.unlink(missing_ok=True)


def decode_records(raw: bytes) -> List[Dict[str, int]]:
    if len(raw) == 0:
        raise RuntimeError("decompressed trace is empty")
    if len(raw) % RECORD_SIZE != 0:
        raise RuntimeError(
            f"decompressed trace size {len(raw)} is not a non-zero multiple of {RECORD_SIZE} bytes"
        )

    records = []
    for off in range(0, len(raw), RECORD_SIZE):
        pc, pc_pa, payload0, payload1, target, instr, mts, branch_type, branch_taken, exception = (
            TRACE_REC.unpack_from(raw, off)
        )
        records.append(
            {
                "orig_pc": pc,
                "pc": pc,
                "pc_pa": pc_pa,
                "payload0": payload0,
                "payload1": payload1,
                "target": target,
                "instr": instr,
                "mts": mts,
                "branch_type": branch_type,
                "branch_taken": branch_taken,
                "exception": exception,
            }
        )
    return records


def encode_records(records: Iterable[Dict[str, int]]) -> bytes:
    buf = bytearray()
    for rec in records:
        buf.extend(
            TRACE_REC.pack(
                rec["pc"],
                rec["pc_pa"],
                rec["payload0"],
                rec["payload1"],
                rec["target"],
                rec["instr"],
                rec["mts"],
                rec["branch_type"],
                rec["branch_taken"],
                rec["exception"],
            )
        )
    return bytes(buf)


def read_sidecar(path: Path) -> Tuple[Optional[str], List[Tuple[int, int, str]]]:
    data = path.read_bytes()
    if data.startswith(SIDECAR_BIN_MAGIC):
        if len(data) < SIDECAR_BIN_HEADER.size:
            raise RuntimeError(f"truncated binary sidecar header in {path}")
        magic, version, mode_value, reserved = SIDECAR_BIN_HEADER.unpack_from(data)
        if magic != SIDECAR_BIN_MAGIC or version != 1 or reserved != 0:
            raise RuntimeError(f"unsupported binary sidecar header in {path}")
        if mode_value != SIDECAR_BIN_MODE_ORDINAL:
            raise RuntimeError(f"unsupported binary sidecar mode in {path}: {mode_value}")
        payload = len(data) - SIDECAR_BIN_HEADER.size
        if payload % SIDECAR_BIN_ENTRY.size:
            raise RuntimeError(f"binary sidecar payload is not entry-aligned in {path}")
        entries = []
        for offset in range(SIDECAR_BIN_HEADER.size, len(data), SIDECAR_BIN_ENTRY.size):
            start, end, tag_value, entry_reserved = SIDECAR_BIN_ENTRY.unpack_from(data, offset)
            if entry_reserved != 0 or tag_value not in SIDECAR_BIN_TAGS:
                raise RuntimeError(f"invalid binary sidecar entry in {path}")
            entries.append((start, end, SIDECAR_BIN_TAGS[tag_value]))
        return "ordinal", entries

    mode: Optional[str] = None
    entries = []
    with io.StringIO(data.decode("ascii")) as f:
        header = f.readline().strip()
        if header != "# trace_pc_start,trace_pc_end,tag":
            raise RuntimeError(f"unexpected sidecar header in {path}: {header!r}")
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                if line == "# sidecar_mode=ordinal":
                    mode = "ordinal"
                elif line == "# sidecar_mode=raw-pc":
                    mode = "raw-pc"
                continue
            start_s, end_s, tag = line.split(",")
            entries.append((int(start_s, 16), int(end_s, 16), tag))
    return mode, entries


def sidecar_tag_for_pc(entries: Sequence[Tuple[int, int, str]], pc: int) -> Optional[str]:
    for start, end, tag in entries:
        if start <= pc < end:
            return tag
    return None


def sidecar_mode_for_entries(records: Sequence[Dict[str, int]],
                             raw_entries: Sequence[Tuple[int, int, str]],
                             declared_mode: Optional[str]) -> str:
    if declared_mode is not None:
        if declared_mode not in ("ordinal", "raw-pc"):
            raise RuntimeError(f"unsupported sidecar mode: {declared_mode}")
        return declared_mode

    if not raw_entries:
        return "raw-pc"

    ordinal_limit = len(records) * INST_SIZE + INST_SIZE
    max_end = max(end for _start, end, _tag in raw_entries)
    if max_end > ordinal_limit:
        return "raw-pc"

    raise RuntimeError(
        "ambiguous low-address sidecar without explicit mode; "
        "add '# sidecar_mode=ordinal' or '# sidecar_mode=raw-pc'"
    )


def synthesize_sidecar(records: Sequence[Dict[str, int]],
                       raw_entries: Sequence[Tuple[int, int, str]],
                       sidecar_mode: Optional[str]) -> List[Tuple[int, int, str]]:
    intervals: List[Tuple[int, int, str]] = []
    pc_to_tag: Dict[int, str] = {}
    conflicted_pcs: set[int] = set()
    ordinal_entries = sorted(raw_entries)
    ordinal_index = 0
    ordinal_mode = sidecar_mode_for_entries(records, raw_entries, sidecar_mode) == "ordinal"

    for index, rec in enumerate(records):
        ordinal_pc = index * INST_SIZE
        tag = None
        if ordinal_mode:
            while (ordinal_index < len(ordinal_entries) and
                   ordinal_entries[ordinal_index][1] <= ordinal_pc):
                ordinal_index += 1

            if ordinal_index < len(ordinal_entries):
                start, end, candidate = ordinal_entries[ordinal_index]
                if start <= ordinal_pc < end:
                    tag = candidate
        else:
            tag = sidecar_tag_for_pc(raw_entries, rec["orig_pc"])
        if tag is None or tag == "none":
            continue

        pc = rec["pc"]
        if pc in conflicted_pcs:
            continue

        existing = pc_to_tag.get(pc)
        if existing is None:
            pc_to_tag[pc] = tag
            continue
        if existing != tag:
            del pc_to_tag[pc]
            conflicted_pcs.add(pc)

    tag_to_pcs: Dict[str, set[int]] = {}
    tag_order: List[str] = []
    for pc, tag in sorted(pc_to_tag.items()):
        if tag not in tag_to_pcs:
            tag_to_pcs[tag] = set()
            tag_order.append(tag)
        tag_to_pcs[tag].add(pc)

    for tag in tag_order:
        pcs = sorted(tag_to_pcs[tag])
        if not pcs:
            continue
        start = pcs[0]
        end = start + INST_SIZE
        for pc in pcs[1:]:
            if pc == end:
                end += INST_SIZE
                continue
            intervals.append((start, end, tag))
            start = pc
            end = pc + INST_SIZE
        intervals.append((start, end, tag))

    return intervals


def write_sidecar(path: Path, intervals: Sequence[Tuple[int, int, str]]) -> None:
    with path.open("w", encoding="ascii") as f:
        f.write("# trace_pc_start,trace_pc_end,tag\n")
        for start, end, tag in intervals:
            f.write(f"0x{start:x},0x{end:x},{tag}\n")


def align_addr(addr: int) -> int:
    return (addr >> 2) << 2


def encode_branch_to_target(pc: int, target: int, *, taken: bool) -> Optional[int]:
    delta = target - pc
    if delta % 2 != 0 or delta < -4096 or delta > 4094:
        return None

    imm = delta & 0x1FFF
    funct3 = 0x0 if taken else 0x1
    return (
        ((imm >> 12) & 0x1) << 31
        | ((imm >> 5) & 0x3F) << 25
        | funct3 << 12
        | ((imm >> 1) & 0xF) << 8
        | ((imm >> 11) & 0x1) << 7
        | OP_BRANCH
    )


def encode_jal_to_target(pc: int, target: int) -> Optional[int]:
    delta = target - pc
    if delta % 2 != 0 or delta < -(1 << 20) or delta > (1 << 20) - 2:
        return None

    imm = delta & 0x1FFFFF
    return (
        ((imm >> 20) & 0x1) << 31
        | ((imm >> 1) & 0x3FF) << 21
        | ((imm >> 11) & 0x1) << 20
        | ((imm >> 12) & 0xFF) << 12
        | OP_JAL
    )


def rewrite_synthetic_control_flow_encodings(records: List[Dict[str, int]]) -> None:
    for rec in records:
        branch_type = rec["branch_type"]
        branch_taken = rec["branch_taken"] != 0
        target = rec["target"]
        pc = rec["pc"]

        # Packing guest PCs may place a genuine taken branch next to its
        # destination. Adjacency in synthetic space does not erase the branch.
        if branch_type == 1:
            if not branch_taken:
                rec["instr"] = encode_branch_to_target(pc, pc, taken=False)
                continue

            encoded = encode_branch_to_target(pc, target, taken=True)
            if encoded is None:
                encoded = encode_jal_to_target(pc, target)
                if encoded is not None:
                    rec["branch_type"] = 2
                else:
                    rec["branch_type"] = 3
                    encoded = OP_JALR
            rec["instr"] = encoded
        elif branch_type == 2:
            encoded = encode_jal_to_target(pc, target)
            if encoded is None:
                rec["branch_type"] = 3
                encoded = OP_JALR
            rec["instr"] = encoded
        elif branch_type == 3:
            rec["instr"] = OP_JALR


def phase1_remap(addresses: Iterable[int]) -> Dict[int, int]:
    collected_addrs = [addr for addr in addresses if addr != 0]
    if not collected_addrs:
        return {}

    origin = collected_addrs[0]
    relative_addrs = sorted({addr - origin for addr in collected_addrs})
    remap: Dict[int, int] = {}
    cur_addr = align_addr(PHASE1_BASE + relative_addrs[0])
    last_relative = relative_addrs[0]

    for relative_addr in relative_addrs:
        addr = origin + relative_addr
        rebased_addr = align_addr(PHASE1_BASE + relative_addr)
        if (last_relative + BIG_JUMP) <= relative_addr and (cur_addr + INST_SIZE) < rebased_addr:
            cur_addr = rebased_addr
        remap[addr] = cur_addr
        cur_addr += INST_SIZE
        last_relative = relative_addr
    return remap


def collect_phase2_blocks(records: Sequence[Dict[str, int]]) -> List[Tuple[int, int]]:
    blocks: List[Tuple[int, int]] = []
    target_pcs = {
        record["target"]
        for record in records
        if (record["branch_taken"] != 0 or record["exception"] != 0) and record["target"] != 0
    }
    block_start = 0

    for index, record in enumerate(records):
        run_start = index == 0 or records[index - 1]["pc"] != record["pc"]
        if index > block_start and run_start and record["pc"] in target_pcs:
            blocks.append((block_start, index))
            block_start = index

        if record["branch_type"] != 0 or record["exception"] != 0:
            blocks.append((block_start, index + 1))
            block_start = index + 1

    if block_start < len(records):
        blocks.append((block_start, len(records)))

    return blocks


def phase2_block_signature(records: Sequence[Dict[str, int]], start: int,
                           end: int) -> Tuple[Tuple[int, int, int], ...]:
    return tuple(
        (
            records[index]["pc"],
            records[index]["branch_type"],
            records[index]["exception"],
        )
        for index in range(start, end)
    )


def allocate_phase2_block_base(start_pc: int, next_free: int) -> int:
    aligned_start = align_addr(start_pc)
    if next_free == 0:
        return aligned_start
    if aligned_start > next_free and (aligned_start - next_free) >= BIG_JUMP:
        return aligned_start
    return next_free


def phase2_block_layout(records: Sequence[Dict[str, int]], start: int,
                        end: int) -> Tuple[List[int], int]:
    first_pc = records[start]["pc"]
    offsets: List[int] = []
    cursor = 0
    index = start

    while index < end:
        run_pc = records[index]["pc"]
        run_len = 1
        next_index = index + 1
        while next_index < end and records[next_index]["pc"] == run_pc:
            run_len += 1
            next_index += 1

        desired_offset = run_pc - first_pc
        if not offsets:
            run_base_offset = 0
        elif desired_offset > cursor and (desired_offset - cursor) >= BIG_JUMP:
            run_base_offset = desired_offset
        else:
            run_base_offset = cursor

        for split_index in range(run_len):
            offsets.append(run_base_offset + split_index * INST_SIZE)

        cursor = run_base_offset + run_len * INST_SIZE
        index = next_index

    return offsets, cursor


def apply_phase2(records: List[Dict[str, int]]) -> None:
    blocks = collect_phase2_blocks(records)
    block_bases: List[int] = []
    signature_to_base: Dict[Tuple[Tuple[int, int, int], ...], int] = {}
    signature_to_layout: Dict[Tuple[Tuple[int, int, int], ...], Tuple[List[int], int]] = {}
    next_free = 0

    for block_index, (start, end) in enumerate(blocks):
        signature = phase2_block_signature(records, start, end)
        layout = signature_to_layout.get(signature)
        if layout is None:
            layout = phase2_block_layout(records, start, end)
            signature_to_layout[signature] = layout
        record_offsets, block_span = layout

        if block_index == 0:
            base_pc = signature_to_base.get(signature)
            if base_pc is None:
                base_pc = allocate_phase2_block_base(records[start]["pc"], next_free)
                signature_to_base[signature] = base_pc
        else:
            prev_record = records[blocks[block_index - 1][1] - 1]
            control_entry = prev_record["branch_taken"] != 0 or prev_record["exception"] != 0
            if control_entry:
                base_pc = signature_to_base.get(signature)
                if base_pc is None:
                    base_pc = allocate_phase2_block_base(records[start]["pc"], next_free)
                    signature_to_base[signature] = base_pc
            else:
                base_pc = records[start - 1]["pc"] + INST_SIZE
                signature_to_base.setdefault(signature, base_pc)

        next_free = max(next_free, base_pc + block_span)
        block_bases.append(base_pc)

        for offset, index in zip(record_offsets, range(start, end)):
            records[index]["pc"] = base_pc + offset

    for block_index, (start, end) in enumerate(blocks[:-1]):
        last_record = records[end - 1]
        if last_record["branch_taken"] != 0 or last_record["exception"] != 0:
            last_record["target"] = block_bases[block_index + 1]


def canonicalize_unresolved_targets(records: List[Dict[str, int]]) -> None:
    executed_pcs = {record["pc"] for record in records}
    if not executed_pcs:
        return

    next_target = align_addr(max(executed_pcs) + BIG_JUMP)
    synthetic_targets: Dict[Tuple[int, int, int, int, int], int] = {}

    for record in records:
        if (record["branch_taken"] == 0 and record["exception"] == 0) or record["target"] == 0:
            continue
        if record["target"] in executed_pcs:
            continue

        site_key = (
            record["pc"],
            record["instr"],
            record["branch_type"],
            record["branch_taken"],
            record["exception"],
        )
        canonical_target = synthetic_targets.get(site_key)
        if canonical_target is None:
            canonical_target = next_target
            synthetic_targets[site_key] = canonical_target
            next_target += INST_SIZE

        record["target"] = canonical_target


def remap_trace(records: List[Dict[str, int]]) -> List[Dict[str, int]]:
    addresses = []
    for rec in records:
        addresses.append(rec["pc"])
        if (rec["branch_type"] != 0 or rec["exception"] != 0) and rec["target"] != 0:
            addresses.append(rec["target"])

    first_pass = phase1_remap(addresses)
    for rec in records:
        rec["pc"] = first_pass.get(rec["pc"], rec["pc"])
        if rec["branch_type"] != 0 or rec["exception"] != 0:
            rec["target"] = first_pass.get(rec["target"], rec["target"])

    apply_phase2(records)
    canonicalize_unresolved_targets(records)
    rewrite_synthetic_control_flow_encodings(records)
    for rec in records:
        # The remapped trace PC is the published user-mode instruction
        # address for translated traces, so keep VA/PA aligned after the
        # synthetic-PC rewrite.
        rec["pc_pa"] = rec["pc"]
    return records


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)
    input_sidecar_csv = Path(f"{input_path}.pc-tags.csv")
    input_sidecar_bin = Path(f"{input_path}.pc-tags.bin")
    if input_sidecar_csv.exists():
        input_sidecar = input_sidecar_csv
    elif input_sidecar_bin.exists():
        input_sidecar = input_sidecar_bin
    else:
        input_sidecar = input_sidecar_csv
    output_sidecar = Path(f"{output_path}.pc-tags.csv")

    try:
        raw = decompress_trace(input_path)
        records = decode_records(raw)
        remapped = remap_trace(records)
        raw_sidecar = read_sidecar(input_sidecar) if input_sidecar.exists() else None

        write_path = output_path
        temp_path = None
        sidecar_write_path = output_sidecar
        sidecar_temp_path = None
        if input_path.resolve() == output_path.resolve():
            temp_path = output_path.with_suffix(output_path.suffix + ".tmp")
            write_path = temp_path
            sidecar_temp_path = Path(f"{temp_path}.pc-tags.csv")
            sidecar_write_path = sidecar_temp_path

        compress_trace(encode_records(remapped), write_path)
        if raw_sidecar is not None:
            raw_sidecar_mode, raw_sidecar_entries = raw_sidecar
            write_sidecar(
                sidecar_write_path,
                synthesize_sidecar(remapped, raw_sidecar_entries, raw_sidecar_mode),
            )

        if temp_path is not None:
            temp_path.replace(output_path)
            if raw_sidecar is not None and sidecar_temp_path is not None:
                sidecar_temp_path.replace(output_sidecar)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
