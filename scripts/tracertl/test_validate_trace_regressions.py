#!/usr/bin/env python3
"""Small regression harness for validate_trace.py field coverage."""

import os
import struct
import subprocess
import sys
import tempfile


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VALIDATOR = os.path.join(REPO_ROOT, "scripts", "tracertl", "validate_trace.py")


def pack_record(*, pc=0x1000, mem_va=0x2000, mem_pa=0x2000, target=0,
                instr=0x00012083, memory_type_and_size=0,
                branch_type=0, branch_taken=0, exception=0):
    return struct.pack(
        "<QQQQQIBBBB",
        pc,
        pc,
        mem_va,
        mem_pa,
        target,
        instr,
        memory_type_and_size,
        branch_type,
        branch_taken,
        exception,
    )


def write_trace(path, memory_type_and_size, *, instr=0x00012083,
                target=0, branch_type=0, branch_taken=0, exception=0):
    rec = pack_record(
        target=target,
        instr=instr,
        memory_type_and_size=memory_type_and_size,
        branch_type=branch_type,
        branch_taken=branch_taken,
        exception=exception,
    )
    with open(path, "wb") as f:
        f.write(rec)
    subprocess.run(["zstd", "-q", "-f", path, "-o", path + ".zst"], check=True)
    return path + ".zst"


def write_records(path, records):
    with open(path, "wb") as f:
        for rec in records:
            f.write(pack_record(**rec))
    subprocess.run(["zstd", "-q", "-f", path, "-o", path + ".zst"], check=True)
    return path + ".zst"


def run_validator(path):
    return subprocess.run(
        [sys.executable, VALIDATOR, path],
        text=True,
        capture_output=True,
        check=False,
    )


def run_validator_with_pythonpath(path, pythonpath):
    env = os.environ.copy()
    current = env.get("PYTHONPATH")
    env["PYTHONPATH"] = pythonpath if not current else pythonpath + os.pathsep + current
    return subprocess.run(
        [sys.executable, VALIDATOR, path],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )


def main():
    with tempfile.TemporaryDirectory(prefix="validate-trace-regressions-") as tmp:
        bad_path = write_trace(os.path.join(tmp, "bad.trace"), 0xF1)
        byte_path = write_trace(os.path.join(tmp, "byte.trace"), 0x01)
        wide_path = write_trace(os.path.join(tmp, "wide.trace"), 0x71)
        cjal_path = write_trace(
            os.path.join(tmp, "cjal.trace"),
            0x00,
            instr=0x00002001,  # RV32C C.JAL quadrant/funct3 shape
            target=0x3000,
            branch_type=2,
            branch_taken=1,
        )
        branch_notgt_path = write_trace(
            os.path.join(tmp, "branch-notgt.trace"),
            0x00,
            instr=0x0080006F,
            branch_type=2,
            branch_taken=1,
        )
        branch_meta_non_branch = write_trace(
            os.path.join(tmp, "branch-meta-on-addi.trace"),
            0x00,
            instr=0x00100093,
            branch_type=2,
        )
        cond_placeholder_taken_ok = write_records(
            os.path.join(tmp, "cond-placeholder-taken-ok.trace"),
            [
                {"pc": 0x2100, "instr": 0x00000063, "target": 0x2100,
                 "branch_type": 1, "branch_taken": 1},
                {"pc": 0x2100, "instr": 0x00100093},
            ],
        )
        cond_placeholder_not_taken_ok = write_records(
            os.path.join(tmp, "cond-placeholder-not-taken-ok.trace"),
            [
                {"pc": 0x2200, "instr": 0x00001063,
                 "branch_type": 1, "branch_taken": 0},
                {"pc": 0x2204, "instr": 0x00100093},
            ],
        )
        cond_placeholder_taken_bad = write_records(
            os.path.join(tmp, "cond-placeholder-taken-bad.trace"),
            [
                {"pc": 0x2300, "instr": 0x00001063, "target": 0x2300,
                 "branch_type": 1, "branch_taken": 1},
                {"pc": 0x2300, "instr": 0x00100093},
            ],
        )
        cond_placeholder_target_bad = write_records(
            os.path.join(tmp, "cond-placeholder-target-bad.trace"),
            [
                {"pc": 0x2500, "instr": 0x00000063, "target": 0x2510,
                 "branch_type": 1, "branch_taken": 1},
                {"pc": 0x2510, "instr": 0x00100093},
            ],
        )
        cond_placeholder_not_taken_bad = write_records(
            os.path.join(tmp, "cond-placeholder-not-taken-bad.trace"),
            [
                {"pc": 0x2400, "instr": 0x00000063,
                 "branch_type": 1, "branch_taken": 0},
                {"pc": 0x2404, "instr": 0x00100093},
            ],
        )
        cond_metadata_on_jal_bad = write_records(
            os.path.join(tmp, "cond-metadata-on-jal-bad.trace"),
            [
                {"pc": 0x2600, "instr": 0x0080006f, "target": 0x2608,
                 "branch_type": 1, "branch_taken": 1},
                {"pc": 0x2608, "instr": 0x00100093},
            ],
        )
        whole_trace_ok = write_records(
            os.path.join(tmp, "whole-ok.trace"),
            [
                {"pc": 0x1000, "instr": 0x00100093},
                {"pc": 0x1004, "instr": 0x00001063, "branch_type": 1, "branch_taken": 0},
                {"pc": 0x1008, "instr": 0x0080006f, "target": 0x1010,
                 "branch_type": 2, "branch_taken": 1},
                {"pc": 0x1010, "instr": 0x0001},
                {"pc": 0x1012, "instr": 0x00100093},
            ],
        )
        whole_trace_bad = write_records(
            os.path.join(tmp, "whole-bad.trace"),
            [
                {"pc": 0x2000, "instr": 0x0080006f, "target": 0x2010,
                 "branch_type": 2, "branch_taken": 1},
                {"pc": 0x2004, "instr": 0x00100093},
            ],
        )
        exception_trace_ok = write_records(
            os.path.join(tmp, "exception-ok.trace"),
            [
                {"pc": 0x3000, "instr": 0x00000073, "target": 0x4000,
                 "exception": 0x81},
                {"pc": 0x4000, "instr": 0x00100093},
            ],
        )
        exception_missing_meta = write_trace(
            os.path.join(tmp, "exception-missing-meta.trace"),
            0x00,
            instr=0x00000073,
            target=0x4000,
        )
        exception_no_target = write_trace(
            os.path.join(tmp, "exception-no-target.trace"),
            0x00,
            instr=0x00000073,
            exception=0x81,
        )
        exception_on_non_trap = write_trace(
            os.path.join(tmp, "exception-on-addi.trace"),
            0x00,
            instr=0x00100093,
            target=0x4000,
            exception=0x81,
        )
        force_jump_exception = write_trace(
            os.path.join(tmp, "force-jump.trace"),
            0x00,
            instr=0,
            target=0x5000,
            exception=0x81,
        )
        fake_zstd_dir = os.path.join(tmp, "fake-zstandard")
        os.mkdir(fake_zstd_dir)
        with open(os.path.join(fake_zstd_dir, "zstandard.py"), "w",
                  encoding="ascii") as f:
            f.write(
                "import io\n"
                "import struct\n"
                "\n"
                "_TRACE = struct.pack(\n"
                "    '<QQQQQIBBBB',\n"
                "    0x1000,\n"
                "    0x1000,\n"
                "    0x2000,\n"
                "    0x2000,\n"
                "    0,\n"
                "    0x00100093,\n"
                "    0,\n"
                "    0,\n"
                "    0,\n"
                "    0,\n"
                ")\n"
                "\n"
                "class _Reader:\n"
                "    def __init__(self, data):\n"
                "        self._buf = io.BytesIO(data)\n"
                "\n"
                "    def read(self, size=-1):\n"
                "        return self._buf.read(size)\n"
                "\n"
                "    def close(self):\n"
                "        self._buf.close()\n"
                "\n"
                "    def __enter__(self):\n"
                "        return self\n"
                "\n"
                "    def __exit__(self, exc_type, exc, tb):\n"
                "        self.close()\n"
                "        return False\n"
                "\n"
                "class ZstdDecompressor:\n"
                "    def decompress(self, raw, max_output_size=None):\n"
                "        raise RuntimeError('streaming path expected')\n"
                "\n"
                "    def stream_reader(self, source):\n"
                "        return _Reader(_TRACE)\n"
                "\n"
                "    def copy_stream(self, source, dest):\n"
                "        dest.write(_TRACE)\n"
                "        return (0, len(_TRACE))\n"
                "\n"
                "__version__ = 'fake'\n"
            )
        fake_zstd_trace = os.path.join(tmp, "fake-zstd.trace.zst")
        with open(fake_zstd_trace, "wb") as f:
            f.write(b"fake-zstd")

        bad = run_validator(bad_path)
        good = run_validator(byte_path)
        wide = run_validator(wide_path)
        cjal = run_validator(cjal_path)
        branch_notgt = run_validator(branch_notgt_path)
        branch_nonbr = run_validator(branch_meta_non_branch)
        cond_taken_ok = run_validator(cond_placeholder_taken_ok)
        cond_not_taken_ok = run_validator(cond_placeholder_not_taken_ok)
        cond_taken_bad = run_validator(cond_placeholder_taken_bad)
        cond_target_bad = run_validator(cond_placeholder_target_bad)
        cond_not_taken_bad = run_validator(cond_placeholder_not_taken_bad)
        cond_on_jal_bad = run_validator(cond_metadata_on_jal_bad)
        whole_ok = run_validator(whole_trace_ok)
        whole_bad = run_validator(whole_trace_bad)
        exception_ok = run_validator(exception_trace_ok)
        exception_missing = run_validator(exception_missing_meta)
        exception_notgt = run_validator(exception_no_target)
        exception_nontrap = run_validator(exception_on_non_trap)
        force_jump = run_validator(force_jump_exception)
        fake_zstd = run_validator_with_pythonpath(fake_zstd_trace, fake_zstd_dir)

        if bad.returncode == 0:
            print("Expected invalid memory_size trace to fail.", file=sys.stderr)
            print(bad.stdout, file=sys.stderr)
            return 1
        if "memory_size outside supported range 0..7" not in bad.stdout:
            print("Validator failed for the wrong reason.", file=sys.stderr)
            print(bad.stdout, file=sys.stderr)
            return 1
        if good.returncode != 0:
            print("Expected byte-sized memory record to pass.", file=sys.stderr)
            print(good.stdout, file=sys.stderr)
            return 1
        if wide.returncode != 0:
            print("Expected 1024-bit memory record to pass.", file=sys.stderr)
            print(wide.stdout, file=sys.stderr)
            return 1
        if cjal.returncode != 0:
            print("Expected RV32C C.JAL branch record to pass.", file=sys.stderr)
            print(cjal.stdout, file=sys.stderr)
            return 1
        if branch_notgt.returncode == 0:
            print("Expected taken-branch-without-target fixture to fail.", file=sys.stderr)
            print(branch_notgt.stdout, file=sys.stderr)
            return 1
        if "taken branch records with target == 0" not in branch_notgt.stdout:
            print("Taken-branch-without-target fixture failed for the wrong reason.", file=sys.stderr)
            print(branch_notgt.stdout, file=sys.stderr)
            return 1
        if branch_nonbr.returncode == 0:
            print("Expected branch-metadata-on-addi fixture to fail.", file=sys.stderr)
            print(branch_nonbr.stdout, file=sys.stderr)
            return 1
        if "branch metadata on non-branch/jump opcode" not in branch_nonbr.stdout:
            print("Branch-metadata-on-addi fixture failed for the wrong reason.", file=sys.stderr)
            print(branch_nonbr.stdout, file=sys.stderr)
            return 1
        if cond_taken_ok.returncode != 0:
            print("Expected taken synthetic conditional placeholder fixture to pass.", file=sys.stderr)
            print(cond_taken_ok.stdout, file=sys.stderr)
            return 1
        if cond_not_taken_ok.returncode != 0:
            print("Expected not-taken synthetic conditional placeholder fixture to pass.", file=sys.stderr)
            print(cond_not_taken_ok.stdout, file=sys.stderr)
            return 1
        if cond_taken_bad.returncode == 0:
            print("Expected taken branch using not-taken placeholder fixture to fail.", file=sys.stderr)
            print(cond_taken_bad.stdout, file=sys.stderr)
            return 1
        if "synthetic conditional branch placeholders disagree with branch_taken" not in cond_taken_bad.stdout:
            print("Taken branch using not-taken placeholder failed for the wrong reason.", file=sys.stderr)
            print(cond_taken_bad.stdout, file=sys.stderr)
            return 1
        if cond_target_bad.returncode == 0:
            print("Expected taken branch with mismatched encoded target fixture to fail.", file=sys.stderr)
            print(cond_target_bad.stdout, file=sys.stderr)
            return 1
        if "taken branch/JAL encodings disagree with target metadata" not in cond_target_bad.stdout:
            print("Taken branch with mismatched encoded target failed for the wrong reason.", file=sys.stderr)
            print(cond_target_bad.stdout, file=sys.stderr)
            return 1
        if cond_not_taken_bad.returncode == 0:
            print("Expected not-taken branch using taken placeholder fixture to fail.", file=sys.stderr)
            print(cond_not_taken_bad.stdout, file=sys.stderr)
            return 1
        if "synthetic conditional branch placeholders disagree with branch_taken" not in cond_not_taken_bad.stdout:
            print("Not-taken branch using taken placeholder failed for the wrong reason.", file=sys.stderr)
            print(cond_not_taken_bad.stdout, file=sys.stderr)
            return 1
        if cond_on_jal_bad.returncode == 0:
            print("Expected conditional metadata on JAL opcode fixture to fail.", file=sys.stderr)
            print(cond_on_jal_bad.stdout, file=sys.stderr)
            return 1
        if "branch_type metadata that disagrees with RV opcode class" not in cond_on_jal_bad.stdout:
            print("Conditional metadata on JAL opcode fixture failed for the wrong reason.", file=sys.stderr)
            print(cond_on_jal_bad.stdout, file=sys.stderr)
            return 1
        if whole_ok.returncode != 0:
            print("Expected whole-trace control-flow fixture to pass.", file=sys.stderr)
            print(whole_ok.stdout, file=sys.stderr)
            return 1
        if whole_bad.returncode == 0:
            print("Expected bad whole-trace control-flow fixture to fail.", file=sys.stderr)
            print(whole_bad.stdout, file=sys.stderr)
            return 1
        if "adjacent record pairs violate whole-trace next-PC control flow" not in whole_bad.stdout:
            print("Whole-trace control-flow fixture failed for the wrong reason.", file=sys.stderr)
            print(whole_bad.stdout, file=sys.stderr)
            return 1
        if exception_ok.returncode != 0:
            print("Expected exception-target whole-trace fixture to pass.", file=sys.stderr)
            print(exception_ok.stdout, file=sys.stderr)
            return 1
        if exception_missing.returncode == 0:
            print("Expected trap-without-exception-metadata fixture to fail.", file=sys.stderr)
            print(exception_missing.stdout, file=sys.stderr)
            return 1
        if "trap-producing records with exception == 0" not in exception_missing.stdout:
            print("Trap-without-exception-metadata fixture failed for the wrong reason.", file=sys.stderr)
            print(exception_missing.stdout, file=sys.stderr)
            return 1
        if exception_notgt.returncode == 0:
            print("Expected exception-without-target fixture to fail.", file=sys.stderr)
            print(exception_notgt.stdout, file=sys.stderr)
            return 1
        if "exception records with target == 0" not in exception_notgt.stdout:
            print("Exception-without-target fixture failed for the wrong reason.", file=sys.stderr)
            print(exception_notgt.stdout, file=sys.stderr)
            return 1
        if exception_nontrap.returncode != 0:
            print("Expected exception-on-addi fixture to pass.", file=sys.stderr)
            print(exception_nontrap.stdout, file=sys.stderr)
            return 1
        if force_jump.returncode != 0:
            print("Expected force-jump exception fixture to pass.", file=sys.stderr)
            print(force_jump.stdout, file=sys.stderr)
            return 1
        if fake_zstd.returncode != 0:
            print("Expected validator to support streaming Python zstandard decompression.", file=sys.stderr)
            print(fake_zstd.stdout, file=sys.stderr)
            print(fake_zstd.stderr, file=sys.stderr)
            return 1

        print("PASS: invalid memory_size is rejected, exception records may truthfully annotate non-SYSTEM opcodes or force-jump placeholders, taken branches and exceptions require targets, trap opcodes require exception metadata, RV32C C.JAL is accepted, whole-trace next-PC control flow handles branches and exceptions, and Python zstandard decompression streams successfully")
        return 0


if __name__ == "__main__":
    sys.exit(main())
