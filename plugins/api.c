/*
 * QEMU Plugin API — RISC-V trace emission bridge
 *
 * The TracerTL RV trace provider now lives in TCG core.
 * This file keeps only the public plugin-facing wrappers.
 *
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 * Copyright (C) 2019, Linaro
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/plugin.h"
#include "tcg/tcg.h"

int qemu_plugin_tb_emit_rv_tagged(uint32_t *buf, uint8_t *tags, int buf_size,
                                  int *insn_offsets,
                                  qemu_plugin_rv_insn_meta *insn_meta,
                                  int *n_guest_insns)
{
    return tcg_tb_emit_rv_tagged(buf, tags, buf_size, insn_offsets,
                                 insn_meta, n_guest_insns);
}

int qemu_plugin_tb_emit_rv(uint32_t *buf, int buf_size,
                           int *insn_offsets,
                           qemu_plugin_rv_insn_meta *insn_meta,
                           int *n_guest_insns)
{
    return tcg_tb_emit_rv(buf, buf_size, insn_offsets, insn_meta,
                          n_guest_insns);
}
