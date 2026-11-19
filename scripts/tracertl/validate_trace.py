#!/usr/bin/env python3
"""
Trace validation tool for TracerTL output.

Exit status: 0 = PASS, 1 = FAIL.

Modes (--mode):
  qemu-user (default): user-mode QEMU traces (VA == PA, mem_pa must be set)
  nemu: NEMU bare-metal traces (VA != PA expected; mem_pa == 0 is allowed)

P0 checks (fatal — any failure → exit 1):
  - File exists and decompresses successfully
  - Decompressed size is a non-zero multiple of 48 bytes
  - Every load/store/AMO opcode has non-zero memory_type metadata
  - Every memory record has memory_size in the supported range 0..7
  - No memory metadata (memory_type != 0) on non-load/store/AMO opcodes
  - No branch metadata (branch_taken != 0) on non-branch/jump opcodes
  - Every non-exception instruction has a valid RISC-V opcode (not 0x7f reserved)
  - No all-zero instruction encodings on non-exception records
  - Every taken branch must have a non-zero branch_type
  - Every taken branch must have a non-zero target
  - Every trap-producing RISC-V opcode must have non-zero exception metadata
  - Every exception record must have a non-zero redirect target
  - Exception metadata may appear on non-SYSTEM opcodes and on instr == 0
    redirect placeholders when the trace contract uses them truthfully
  - [qemu-user only] Every memory record with non-zero mem_va must also have
    non-zero mem_pa

P1 warnings (reported, do not affect exit code):
  - VA != PA in user-mode traces
  - Load/store record with mem_va == 0
  - Memory record with mem_pa != mem_va (expected in kernel/nemu mode)
  - NOP (addi x0,x0,0 = 0x00000013) records present
    (legal instruction, but high counts may indicate TCG placeholder pollution)
  - [nemu only] Memory record with mem_va != 0 but mem_pa == 0
    (NEMU does not populate mem_pa; this is expected)

Note: addi x0, x0, 0 (0x00000013) IS a legal RISC-V NOP and does NOT cause
a P0 failure. Instruction 0xffffffff has opcode 0x7f (reserved) and IS fatal.

Usage:
  python3 validate_trace.py trace.zst [--max-records N] [--mode qemu-user|nemu]
"""
import argparse
import io
import os
import struct
import subprocess
import sys

RECORD_SIZE = 48

# 32-bit RISC-V opcodes (bits 6:0)
OPCODE_MASK  = 0x7f
OP_LOAD      = 0x03   # lb, lh, lw, ld, lbu, lhu, lwu
OP_LOAD_FP   = 0x07   # flw, fld
OP_STORE     = 0x23   # sb, sh, sw, sd
OP_STORE_FP  = 0x27   # fsw, fsd
OP_AMO       = 0x2f   # lr, sc, amoswap, ...
OP_BRANCH    = 0x63   # beq, bne, blt, bge, bltu, bgeu
OP_JAL       = 0x6f
OP_JALR      = 0x67

SYNTH_COND_TAKEN_PLACEHOLDER = 0x00000063   # beq x0, x0, 0
SYNTH_COND_NOT_TAKEN_PLACEHOLDER = 0x00001063  # bne x0, x0, 0

# Valid 32-bit opcodes (bits[1:0] == 11, bits[6:0] != 0x7f).
# 0x7f (all-ones in lower 7 bits) is reserved — no base RV instruction uses it.
VALID_OPCODES_32 = frozenset({
    0x03, 0x07, 0x0f, 0x13, 0x17, 0x1b,  # LOAD, LOAD-FP, MISC-MEM, OP-IMM, AUIPC, OP-IMM-32
    0x23, 0x27, 0x2f, 0x33, 0x37, 0x3b,  # STORE, STORE-FP, AMO, OP, LUI, OP-32
    0x43, 0x47, 0x4b, 0x4f, 0x53,        # MADD, MSUB, NMSUB, NMADD, OP-FP
    0x57,                                  # OP-V (vector)
    0x5b,                                  # custom-1
    0x63, 0x67, 0x6f, 0x73,              # BRANCH, JALR, JAL, SYSTEM
    0x7b,                                  # custom-3
    # 0x0b, 0x1f, 0x3f, 0x5f, 0x6b, 0x77  -- reserved; excluded
})


def is_compressed(instr):
    """True if this is a 16-bit RVC instruction (bits[1:0] != 0b11)."""
    return (instr & 0x3) != 0x3 and instr != 0


def is_valid_rv_encoding(instr):
    """
    Return True if instr is a plausibly valid RISC-V encoding.

    32-bit (bits 1:0 == 11): opcode must be in VALID_OPCODES_32.
    16-bit (bits 1:0 != 11): any non-zero quadrant value is plausible.
    Zero (0x00000000): always ILLEGAL.
    """
    if instr == 0:
        return False  # all-zeros = ILLEGAL
    if (instr & 0x3) != 0x3:
        # 16-bit compressed: quadrant 0/1/2 are all legal namespaces
        return True
    # 32-bit: check opcode
    return (instr & OPCODE_MASK) in VALID_OPCODES_32


def is_load(instr):
    if is_compressed(instr):
        op = instr & 0x03
        f3 = (instr >> 13) & 0x07
        if op == 0x00:
            # C.FLD(1), C.LW(2), C.LD(3)
            return f3 in (0x01, 0x02, 0x03)
        if op == 0x02:
            # C.FLDSP(1), C.LWSP(2), C.LDSP(3)
            return f3 in (0x01, 0x02, 0x03)
        return False
    opc = instr & OPCODE_MASK
    return opc in (OP_LOAD, OP_LOAD_FP, OP_AMO)


def is_store(instr):
    if is_compressed(instr):
        op = instr & 0x03
        f3 = (instr >> 13) & 0x07
        if op == 0x00:
            # C.FSD(5), C.SW(6), C.SD(7)
            return f3 in (0x05, 0x06, 0x07)
        if op == 0x02:
            # C.FSDSP(5), C.SWSP(6), C.SDSP(7)
            return f3 in (0x05, 0x06, 0x07)
        return False
    opc = instr & OPCODE_MASK
    return opc in (OP_STORE, OP_STORE_FP)


def is_branch_or_jump(instr, branch_type=0):
    if is_compressed(instr):
        op = instr & 0x03
        f3 = (instr >> 13) & 0x07
        if op == 0x01:
            # C.JAL(1, RV32C call), C.J(5), C.BEQZ(6), C.BNEZ(7)
            return f3 in (0x05, 0x06, 0x07) or (f3 == 0x01 and branch_type == 2)
        if op == 0x02 and f3 == 0x04:
            # C.JR and C.JALR: funct3=100, rs2=0, rs1!=0
            rs2 = (instr >> 2) & 0x1f
            rs1 = (instr >> 7) & 0x1f
            return rs2 == 0 and rs1 != 0
        return False
    opc = instr & OPCODE_MASK
    return opc in (OP_BRANCH, OP_JAL, OP_JALR)


def is_nop(instr):
    return instr == 0x00000013  # addi x0, x0, 0


def instruction_size(instr):
    return 2 if is_compressed(instr) else 4


def sign_extend(value, bits):
    sign_bit = 1 << (bits - 1)
    return (value ^ sign_bit) - sign_bit


def branch_target_from_instr(pc, instr):
    if is_compressed(instr):
        return None
    if (instr & OPCODE_MASK) != OP_BRANCH:
        return None
    imm = (
        ((instr >> 31) & 0x1) << 12
        | ((instr >> 7) & 0x1) << 11
        | ((instr >> 25) & 0x3f) << 5
        | ((instr >> 8) & 0xf) << 1
    )
    return (pc + sign_extend(imm, 13)) & 0xffffffffffffffff


def jal_target_from_instr(pc, instr):
    if is_compressed(instr):
        return None
    if (instr & OPCODE_MASK) != OP_JAL:
        return None
    imm = (
        ((instr >> 31) & 0x1) << 20
        | ((instr >> 12) & 0xff) << 12
        | ((instr >> 20) & 0x1) << 11
        | ((instr >> 21) & 0x3ff) << 1
    )
    return (pc + sign_extend(imm, 21)) & 0xffffffffffffffff


def encoded_taken_target(pc, instr):
    if is_compressed(instr):
        return None
    opc = instr & OPCODE_MASK
    if opc == OP_BRANCH:
        return branch_target_from_instr(pc, instr)
    if opc == OP_JAL:
        return jal_target_from_instr(pc, instr)
    return None


def expected_branch_type_for_instr(instr, branch_type=0):
    if is_compressed(instr):
        op = instr & 0x03
        f3 = (instr >> 13) & 0x07
        if op == 0x01:
            if f3 in (0x05,):
                return 2
            if f3 in (0x06, 0x07):
                return 1
            if f3 == 0x01 and branch_type == 2:
                return 2
        if op == 0x02 and f3 == 0x04:
            rs2 = (instr >> 2) & 0x1f
            rs1 = (instr >> 7) & 0x1f
            if rs2 == 0 and rs1 != 0:
                return 3
        return 0

    opc = instr & OPCODE_MASK
    if opc == OP_BRANCH:
        return 1
    if opc == OP_JAL:
        return 2
    if opc == OP_JALR:
        return 3
    return 0


def requires_exception_metadata(instr):
    if instr == 0:
        return False

    if is_compressed(instr):
        op = instr & 0x03
        funct3 = (instr >> 13) & 0x07
        if op == 0x02 and funct3 == 0x04:
            bit12 = (instr >> 12) & 0x01
            rs2 = (instr >> 2) & 0x1f
            rs1 = (instr >> 7) & 0x1f
            return bit12 == 1 and rs1 == 0 and rs2 == 0
        return False

    if (instr & OPCODE_MASK) != 0x73:
        return False
    if ((instr >> 12) & 0x7) != 0:
        return False
    if ((instr >> 7) & 0x1f) != 0 or ((instr >> 15) & 0x1f) != 0:
        return False

    imm12 = instr >> 20
    return imm12 in (0x000, 0x001)


def decompress_zst(path):
    """
    Decompress a .zst/.zstd file.  Returns raw bytes on success.
    Exits with a clear error message on any failure.
    """
    if not os.path.exists(path):
        sys.exit(f"FAIL [P0]: file not found: {path}")
    if os.path.getsize(path) == 0:
        sys.exit(f"FAIL [P0]: file is empty: {path}")

    # Try zstandard Python package
    try:
        import zstandard as zstd
        dctx = zstd.ZstdDecompressor()
        try:
            with open(path, 'rb') as f:
                if hasattr(dctx, 'stream_reader'):
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
        except Exception as e:
            sys.exit(f"FAIL [P0]: zstandard decompression failed: {e}")
    except ImportError:
        pass

    # Fallback: zstd CLI
    try:
        result = subprocess.run(
            ['zstd', '-d', '-c', '--', path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
    except FileNotFoundError:
        sys.exit("FAIL [P0]: neither 'zstandard' Python package nor 'zstd' CLI available")

    if result.returncode != 0:
        stderr = result.stderr.decode(errors='replace').strip()
        sys.exit(f"FAIL [P0]: zstd decompression failed (exit {result.returncode}): {stderr}")

    if not result.stdout:
        sys.exit(f"FAIL [P0]: zstd produced no output for '{path}' — not a valid .zst file?")

    return result.stdout


def parse_record(data, offset):
    """Parse one 48-byte TraceInstruction record.

    Layout (little-endian):
      [0]  uint64 instr_pc_va
      [1]  uint64 instr_pc_pa
      [2]  uint64 exu_data.memory_address.va  (or arthi_src.src0)
      [3]  uint64 exu_data.memory_address.pa  (or arthi_src.src1)
      [4]  uint64 target
      [5]  uint32 instr
      [6]  uint8  memory_type_and_size  (low4=type, high4=size)
      [7]  uint8  branch_type
      [8]  uint8  branch_taken
      [9]  uint8  exception
    """
    fields = struct.unpack_from('<QQQQQIBBBB', data, offset)
    return {
        'instr_pc_va':   fields[0],
        'instr_pc_pa':   fields[1],
        'mem_va':        fields[2],
        'mem_pa':        fields[3],
        'target':        fields[4],
        'instr':         fields[5],
        'memory_type':   fields[6] & 0x0f,
        'memory_size':   (fields[6] >> 4) & 0x0f,
        'branch_type':   fields[7],
        'branch_taken':  fields[8],
        'exception':     fields[9],
    }


def validate(path, max_records=0, mode='qemu-user'):
    data = decompress_zst(path)

    # P0: record alignment
    if len(data) % RECORD_SIZE != 0:
        print(f"FAIL [P0]: decompressed size {len(data)} is not a multiple of {RECORD_SIZE}")
        sys.exit(1)

    n_records = len(data) // RECORD_SIZE

    # P0: non-empty
    if n_records == 0:
        print(f"FAIL [P0]: trace is empty (zero records)")
        sys.exit(1)

    if max_records > 0:
        n_records = min(n_records, max_records)

    total = 0
    ldst_without_mem    = 0
    mem_on_non_ldst     = 0
    branch_on_non_br    = 0
    illegal_encoding    = 0
    va_pa_mismatch      = 0
    mem_zero_addr       = 0   # memory_type != 0 but mem_va == 0
    mem_pa_zero         = 0   # memory_type != 0, mem_va != 0, but mem_pa == 0
    mem_pa_va_mismatch  = 0   # memory_type != 0, mem_pa != mem_va (kernel mode)
    mem_size_bad        = 0   # memory_type != 0, but memory_size is outside supported range
    branch_no_target    = 0   # branch_taken != 0 but target == 0
    branch_no_type      = 0   # branch_taken != 0 but branch_type == 0
    cond_placeholder_direction_bad = 0
    encoded_target_bad  = 0   # taken branch/JAL immediate disagrees with target metadata
    branch_type_mismatch = 0  # branch_type metadata disagrees with RV opcode class
    exception_missing   = 0   # trap-producing opcode with exception == 0
    exception_no_target = 0   # exception != 0 but target == 0
    next_pc_bad         = 0   # adjacent record pc progression mismatches
    nop_count           = 0
    mem_records         = 0
    branch_records      = 0

    first_ldst_no_mem    = None
    first_mem_nonldst    = None
    first_br_nonbr       = None
    first_illegal        = None
    first_mem_zero       = None
    first_mem_pa_zero    = None
    first_mem_size_bad   = None
    first_branch_notgt   = None
    first_branch_no_type = None
    first_cond_placeholder_direction_bad = None
    first_encoded_target_bad = None
    first_branch_type_mismatch = None
    first_exception_missing = None
    first_exception_notgt = None
    first_next_pc_bad    = None
    first_nop            = None
    prev_rec             = None

    for i in range(n_records):
        rec = parse_record(data, i * RECORD_SIZE)
        total += 1
        pc    = rec['instr_pc_va']
        instr = rec['instr']
        mt    = rec['memory_type']
        bt    = rec['branch_taken']
        exc   = rec['exception']
        mv    = rec['mem_va']
        tgt   = rec['target']

        if prev_rec is not None:
            if prev_rec['exception'] != 0 and prev_rec['target'] != 0:
                expected_pc = prev_rec['target']
            elif prev_rec['branch_taken'] != 0 and prev_rec['target'] != 0:
                expected_pc = prev_rec['target']
            else:
                expected_pc = (prev_rec['instr_pc_va'] +
                               instruction_size(prev_rec['instr']))

            if pc != expected_pc:
                if next_pc_bad == 0:
                    first_next_pc_bad = (
                        i - 1,
                        prev_rec['instr_pc_va'],
                        prev_rec['instr'],
                        expected_pc,
                        i,
                        pc,
                    )
                next_pc_bad += 1

        # P1: VA == PA
        if rec['instr_pc_va'] != rec['instr_pc_pa']:
            va_pa_mismatch += 1

        # P0: RV encoding legality
        if not (exc != 0 and instr == 0) and not is_valid_rv_encoding(instr):
            if illegal_encoding == 0:
                first_illegal = (i, pc, instr)
            illegal_encoding += 1

        # P1: NOP count (legal instruction, but track for pollution detection)
        if is_nop(instr):
            if nop_count == 0:
                first_nop = (i, pc)
            nop_count += 1

        # P0: memory metadata correlation
        mem_op = is_load(instr) or is_store(instr)
        if mem_op:
            if mt == 0:
                if ldst_without_mem == 0:
                    first_ldst_no_mem = (i, pc, instr)
                ldst_without_mem += 1
        else:
            if mt != 0:
                if mem_on_non_ldst == 0:
                    first_mem_nonldst = (i, pc, instr)
                mem_on_non_ldst += 1
        if mt != 0:
            mem_records += 1
            if rec['memory_size'] > 7:
                if mem_size_bad == 0:
                    first_mem_size_bad = (i, pc, instr, rec['memory_size'])
                mem_size_bad += 1
            # P1: memory address should be non-zero
            if mv == 0:
                if mem_zero_addr == 0:
                    first_mem_zero = (i, pc, instr)
                mem_zero_addr += 1
            else:
                # mem_pa == 0 check: P0 for qemu-user (VA==PA expected),
                # P1 for nemu (bare-metal does not populate mem_pa)
                if rec['mem_pa'] == 0:
                    if mem_pa_zero == 0:
                        first_mem_pa_zero = (i, pc, instr, mv)
                    mem_pa_zero += 1
                # P1: for user-mode traces, mem_pa should equal mem_va
                elif rec['mem_pa'] != mv:
                    mem_pa_va_mismatch += 1

        # P0: branch metadata correlation
        if rec['branch_type'] != 0 or bt != 0:
            branch_records += 1
            if not is_branch_or_jump(instr, rec['branch_type']):
                if branch_on_non_br == 0:
                    first_br_nonbr = (i, pc, instr)
                branch_on_non_br += 1
            else:
                expected_branch_type = expected_branch_type_for_instr(
                    instr, rec['branch_type'])
                if (rec['branch_type'] != 0 and expected_branch_type != 0 and
                        rec['branch_type'] != expected_branch_type):
                    if branch_type_mismatch == 0:
                        first_branch_type_mismatch = (
                            i, pc, instr, rec['branch_type'],
                            expected_branch_type)
                    branch_type_mismatch += 1
                if rec['branch_type'] == 1:
                    if instr == SYNTH_COND_TAKEN_PLACEHOLDER and bt == 0:
                        if cond_placeholder_direction_bad == 0:
                            first_cond_placeholder_direction_bad = (
                                i, pc, instr, bt)
                        cond_placeholder_direction_bad += 1
                    elif instr == SYNTH_COND_NOT_TAKEN_PLACEHOLDER and bt != 0:
                        if cond_placeholder_direction_bad == 0:
                            first_cond_placeholder_direction_bad = (
                                i, pc, instr, bt)
                        cond_placeholder_direction_bad += 1
                if bt != 0:
                    # P0: taken branch should have a target
                    if tgt == 0:
                        if branch_no_target == 0:
                            first_branch_notgt = (i, pc, instr)
                        branch_no_target += 1
                    # P0: taken branch must have a non-zero branch_type
                    if rec['branch_type'] == 0:
                        if branch_no_type == 0:
                            first_branch_no_type = (i, pc, instr)
                        branch_no_type += 1
                    encoded_target = encoded_taken_target(pc, instr)
                    if encoded_target is not None and tgt != 0 and encoded_target != tgt:
                        if encoded_target_bad == 0:
                            first_encoded_target_bad = (
                                i, pc, instr, encoded_target, tgt)
                        encoded_target_bad += 1

        if requires_exception_metadata(instr) and exc == 0:
            if exception_missing == 0:
                first_exception_missing = (i, pc, instr)
            exception_missing += 1

        if exc != 0:
            if tgt == 0:
                if exception_no_target == 0:
                    first_exception_notgt = (i, pc, instr, exc)
                exception_no_target += 1

        prev_rec = rec

    # --- Report ---
    print(f"=== Trace Validation: {path} (mode={mode}) ===")
    print(f"Total records     : {total}")
    print(f"Memory records    : {mem_records}")
    print(f"Branch records    : {branch_records}")
    print()

    p0_fail = False

    def p0(msg):
        nonlocal p0_fail
        print(f"FAIL [P0]: {msg}")
        p0_fail = True

    if illegal_encoding > 0:
        p0(f"{illegal_encoding} records with invalid RV encoding (e.g. opcode 0x7f or all-zero)")
        if first_illegal:
            i, pc, instr = first_illegal
            print(f"  First at record {i}: pc=0x{pc:016x} instr=0x{instr:08x}")
    else:
        print("PASS: all instruction encodings are valid RISC-V")

    if ldst_without_mem > 0:
        p0(f"{ldst_without_mem} load/store/AMO records with memory_type == 0")
        if first_ldst_no_mem:
            i, pc, instr = first_ldst_no_mem
            print(f"  First at record {i}: pc=0x{pc:016x} instr=0x{instr:08x}")
    else:
        print("PASS: all load/store/AMO records have memory metadata")

    if mem_on_non_ldst > 0:
        p0(f"{mem_on_non_ldst} records with memory_type != 0 on non-ld/st opcode")
        if first_mem_nonldst:
            i, pc, instr = first_mem_nonldst
            print(f"  First at record {i}: pc=0x{pc:016x} instr=0x{instr:08x}")
    else:
        print("PASS: memory metadata only on load/store/AMO opcodes")

    if mem_size_bad > 0:
        p0(f"{mem_size_bad} memory records with memory_size outside supported range 0..7")
        if first_mem_size_bad:
            i, pc, instr, memory_size = first_mem_size_bad
            print(f"  First at record {i}: pc=0x{pc:016x} instr=0x{instr:08x} memory_size={memory_size}")
    else:
        print("PASS: all memory records use a valid memory_size encoding")

    if branch_on_non_br > 0:
        p0(f"{branch_on_non_br} records with branch metadata on non-branch/jump opcode")
        if first_br_nonbr:
            i, pc, instr = first_br_nonbr
            print(f"  First at record {i}: pc=0x{pc:016x} instr=0x{instr:08x}")
    else:
        print("PASS: branch metadata only on branch/jump opcodes")

    if cond_placeholder_direction_bad > 0:
        p0(f"{cond_placeholder_direction_bad} synthetic conditional branch placeholders disagree with branch_taken")
        if first_cond_placeholder_direction_bad:
            i, pc, instr, bt = first_cond_placeholder_direction_bad
            print(f"  First at record {i}: pc=0x{pc:016x} instr=0x{instr:08x} branch_taken={bt}")
    else:
        print("PASS: synthetic conditional branch placeholders match branch_taken")

    if encoded_target_bad > 0:
        p0(f"{encoded_target_bad} taken branch/JAL encodings disagree with target metadata")
        if first_encoded_target_bad:
            i, pc, instr, encoded_target, tgt = first_encoded_target_bad
            print(
                f"  First at record {i}: pc=0x{pc:016x} instr=0x{instr:08x} "
                f"encoded_target=0x{encoded_target:016x} target=0x{tgt:016x}"
            )
    else:
        print("PASS: taken branch/JAL encodings agree with target metadata")

    if branch_type_mismatch > 0:
        p0(f"{branch_type_mismatch} branch records with branch_type metadata that disagrees with RV opcode class")
        if first_branch_type_mismatch:
            i, pc, instr, observed, expected = first_branch_type_mismatch
            print(
                f"  First at record {i}: pc=0x{pc:016x} instr=0x{instr:08x} "
                f"branch_type={observed} expected={expected}"
            )
    else:
        print("PASS: branch_type metadata matches branch/jump opcode class")

    # mem_pa == 0: P0 for qemu-user, P1 for nemu
    if mem_pa_zero > 0:
        if mode == 'qemu-user':
            p0(f"{mem_pa_zero} memory records with mem_va != 0 but mem_pa == 0")
            if first_mem_pa_zero:
                i, pc, instr, mv = first_mem_pa_zero
                print(f"  First at record {i}: pc=0x{pc:016x} instr=0x{instr:08x} mem_va=0x{mv:016x}")
        else:
            print(f"WARN [P1]: {mem_pa_zero} memory records with mem_va != 0 but mem_pa == 0"
                  f" (expected for nemu traces)")
            if first_mem_pa_zero:
                i, pc, instr, mv = first_mem_pa_zero
                print(f"  First at record {i}: pc=0x{pc:016x} instr=0x{instr:08x} mem_va=0x{mv:016x}")
    else:
        print("PASS: all memory records with non-zero mem_va also have non-zero mem_pa")

    if branch_no_type > 0:
        p0(f"{branch_no_type} taken branch records with branch_type == 0")
        if first_branch_no_type:
            i, pc, instr = first_branch_no_type
            print(f"  First at record {i}: pc=0x{pc:016x} instr=0x{instr:08x}")
    else:
        print("PASS: all taken branches have a non-zero branch_type")

    if branch_no_target > 0:
        p0(f"{branch_no_target} taken branch records with target == 0")
        if first_branch_notgt:
            i, pc, instr = first_branch_notgt
            print(f"  First at record {i}: pc=0x{pc:016x} instr=0x{instr:08x}")
    else:
        print("PASS: all taken branches have a non-zero target")

    if exception_missing > 0:
        p0(f"{exception_missing} trap-producing records with exception == 0")
        if first_exception_missing:
            i, pc, instr = first_exception_missing
            print(f"  First at record {i}: pc=0x{pc:016x} instr=0x{instr:08x}")
    else:
        print("PASS: all trap-producing records carry exception metadata")

    if exception_no_target > 0:
        p0(f"{exception_no_target} exception records with target == 0")
        if first_exception_notgt:
            i, pc, instr, exc = first_exception_notgt
            print(f"  First at record {i}: pc=0x{pc:016x} instr=0x{instr:08x} exception=0x{exc:02x}")
    else:
        print("PASS: all exception records have a non-zero redirect target")

    if next_pc_bad > 0:
        p0(f"{next_pc_bad} adjacent record pairs violate whole-trace next-PC control flow")
        if first_next_pc_bad:
            prev_i, prev_pc, prev_instr, expected_pc, i, pc = first_next_pc_bad
            print(f"  First at records {prev_i}->{i}: prev_pc=0x{prev_pc:016x} prev_instr=0x{prev_instr:08x}")
            print(f"  Expected next pc=0x{expected_pc:016x}, got 0x{pc:016x}")
    else:
        print("PASS: whole-trace next-PC control flow is consistent")

    if va_pa_mismatch > 0:
        print(f"WARN [P1]: {va_pa_mismatch} records where instr_pc_va != instr_pc_pa")
    else:
        print("PASS: instr_pc_va == instr_pc_pa for all records")

    if mem_zero_addr > 0:
        print(f"WARN [P1]: {mem_zero_addr} memory records with mem_va == 0")
        if first_mem_zero:
            i, pc, instr = first_mem_zero
            print(f"  First at record {i}: pc=0x{pc:016x} instr=0x{instr:08x}")
    else:
        print("PASS: all memory records have non-zero address")

    if mem_pa_va_mismatch > 0:
        print(f"WARN [P1]: {mem_pa_va_mismatch} memory records where mem_pa != mem_va (expected in kernel mode)")

    if nop_count > 0:
        nop_pct = 100.0 * nop_count / total
        print(f"WARN [P1]: {nop_count} NOP (0x00000013) records ({nop_pct:.1f}% of total)")
        if first_nop:
            i, pc = first_nop
            print(f"  First at record {i}: pc=0x{pc:016x}")
        if nop_pct > 10.0:
            print("  (>10% NOP rate may indicate TCG placeholder pollution)")

    print()
    print("OVERALL:", "FAIL" if p0_fail else "PASS")
    if p0_fail:
        sys.exit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Validate TracerTL trace files')
    parser.add_argument('trace', help='Path to .zst/.zstd trace file')
    parser.add_argument('--max-records', type=int, default=0,
                        help='Max records to check (0 = all)')
    parser.add_argument('--mode', choices=['qemu-user', 'nemu'], default='qemu-user',
                        help='Trace source mode: qemu-user (default) or nemu. '
                             'In nemu mode mem_pa==0 is a P1 warning, not a P0 failure.')
    args = parser.parse_args()
    validate(args.trace, args.max_records, args.mode)
