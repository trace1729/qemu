/*
 * CSV sidecar writer for synthetic trace-PC provenance tags.
 *
 * The writer accepts tagged 4-byte synthetic PCs in dynamic order,
 * suppresses duplicates, and coalesces adjacent PCs with the same tag into
 * half-open intervals written as:
 *
 *   0xSTART_PC,0xEND_PC_EXCLUSIVE,tag_name
 *
 * Raw sidecar consumers can disambiguate this ordinal encoding from guest-PC
 * keyed sidecars via the emitted mode comment.
 */
#ifndef TRACERTL_PC_TAG_SIDECAR_H
#define TRACERTL_PC_TAG_SIDECAR_H

#include <glib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "qemu/qemu-plugin.h"

typedef struct TracertlPcTagSidecarWriter {
    FILE *fp;
    GHashTable *seen_pcs;
    uint64_t interval_start;
    uint64_t interval_end;
    qemu_plugin_rv_trace_tag interval_tag;
    bool have_interval;
    int status;
} TracertlPcTagSidecarWriter;

static inline const char *tracertl_pc_tag_name(qemu_plugin_rv_trace_tag tag)
{
    switch (tag) {
    case QEMU_PLUGIN_RV_TAG_NONE:
        return "none";
    case QEMU_PLUGIN_RV_TAG_MOVCOND:
        return "movcond";
    case QEMU_PLUGIN_RV_TAG_HELPER_PLACEHOLDER:
        return "helper_placeholder";
    case QEMU_PLUGIN_RV_TAG_INDIRECT_BRANCH_PLACEHOLDER:
        return "indirect_branch_placeholder";
    case QEMU_PLUGIN_RV_TAG_GENERIC_DEPENDENCY_PLACEHOLDER:
        return "generic_dependency_placeholder";
    default:
        return "unknown";
    }
}

static inline int tracertl_pc_tag_sidecar_flush_interval(
    TracertlPcTagSidecarWriter *writer)
{
    if (!writer->have_interval) {
        return writer->status;
    }

    if (fprintf(writer->fp, "0x%" PRIx64 ",0x%" PRIx64 ",%s\n",
                writer->interval_start, writer->interval_end,
                tracertl_pc_tag_name(writer->interval_tag)) < 0) {
        writer->status = -1;
    }

    writer->have_interval = false;
    return writer->status;
}

static inline TracertlPcTagSidecarWriter *tracertl_pc_tag_sidecar_open(
    const char *path)
{
    TracertlPcTagSidecarWriter *writer;

    writer = g_new0(TracertlPcTagSidecarWriter, 1);
    writer->fp = fopen(path, "w");
    if (!writer->fp) {
        g_free(writer);
        return NULL;
    }

    writer->seen_pcs = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                             g_free, NULL);
    if (fprintf(writer->fp,
                "# trace_pc_start,trace_pc_end,tag\n"
                "# sidecar_mode=ordinal\n") < 0) {
        g_hash_table_destroy(writer->seen_pcs);
        fclose(writer->fp);
        g_free(writer);
        return NULL;
    }

    return writer;
}

static inline int tracertl_pc_tag_sidecar_note(
    TracertlPcTagSidecarWriter *writer,
    uint64_t pc,
    qemu_plugin_rv_trace_tag tag)
{
    gpointer stored_tag_ptr;

    g_assert(writer != NULL);

    if (writer->status < 0) {
        return -1;
    }

    if (tag == QEMU_PLUGIN_RV_TAG_NONE) {
        return 0;
    }

    stored_tag_ptr = g_hash_table_lookup(writer->seen_pcs, &pc);
    if (stored_tag_ptr != NULL) {
        qemu_plugin_rv_trace_tag stored_tag =
            (qemu_plugin_rv_trace_tag)(GPOINTER_TO_UINT(stored_tag_ptr) - 1);

        if (stored_tag == tag) {
            return 0;
        }

        writer->status = -1;
        return -1;
    }

    {
        uint64_t *key = g_new(uint64_t, 1);

        *key = pc;
        g_hash_table_insert(writer->seen_pcs, key,
                            GUINT_TO_POINTER((unsigned int)tag + 1));
    }

    if (writer->have_interval &&
        writer->interval_tag == tag &&
        writer->interval_end == pc) {
        writer->interval_end += 4;
        return 0;
    }

    if (tracertl_pc_tag_sidecar_flush_interval(writer) < 0) {
        return -1;
    }

    writer->interval_start = pc;
    writer->interval_end = pc + 4;
    writer->interval_tag = tag;
    writer->have_interval = true;
    return 0;
}

static inline int tracertl_pc_tag_sidecar_close(
    TracertlPcTagSidecarWriter *writer)
{
    int status;

    g_assert(writer != NULL);

    status = tracertl_pc_tag_sidecar_flush_interval(writer);
    if (fclose(writer->fp) != 0) {
        status = -1;
    }
    g_hash_table_destroy(writer->seen_pcs);
    g_free(writer);
    return status;
}

#endif
