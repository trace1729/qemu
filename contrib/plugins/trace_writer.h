/*
 * Zstd-compressed trace writer for TraceInstructionC records
 *
 * Header-only library for writing TraceInstruction records to a
 * Zstd-compressed file. Designed for use in QEMU plugins.
 *
 * Usage:
 *   TraceWriter *tw = trace_writer_open("output.zst", 3);
 *   trace_writer_write(tw, &record);
 *   trace_writer_close(tw);
 *
 * Copyright (c) 2026 Institute of Computing Technology, CAS
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TRACE_WRITER_H
#define TRACE_WRITER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <zstd.h>

#include "trace_format_c.h"

/* Buffer size for accumulating records before compression */
#define TRACE_WRITER_BUF_RECORDS 65536
#define TRACE_WRITER_BUF_SIZE \
    (TRACE_WRITER_BUF_RECORDS * sizeof(struct TraceInstructionC))

typedef struct {
    FILE *fp;
    ZSTD_CCtx *cctx;
    ZSTD_CStream *cstream;
    bool raw;

    /* Input buffer: accumulate raw records */
    uint8_t *in_buf;
    size_t in_pos;       /* current write position in in_buf */
    size_t in_capacity;  /* = TRACE_WRITER_BUF_SIZE */

    /* Output buffer: compressed data */
    uint8_t *out_buf;
    size_t out_capacity;

    /* Statistics */
    uint64_t records_written;
    uint64_t uncompressed_bytes_written;
} TraceWriter;

static inline TraceWriter *trace_writer_open(const char *path, int level)
{
    TraceWriter *tw = (TraceWriter *)calloc(1, sizeof(TraceWriter));
    if (!tw) {
        return NULL;
    }

    tw->fp = fopen(path, "wb");
    if (!tw->fp) {
        free(tw);
        return NULL;
    }

    tw->raw = (level == 0);
    if (!tw->raw) {
        tw->cstream = ZSTD_createCStream();
        if (!tw->cstream) {
            fclose(tw->fp);
            free(tw);
            return NULL;
        }

        size_t ret = ZSTD_CCtx_setParameter(tw->cstream, ZSTD_c_compressionLevel,
                                            level);
        if (ZSTD_isError(ret)) {
            ZSTD_freeCStream(tw->cstream);
            fclose(tw->fp);
            free(tw);
            return NULL;
        }
    }

    tw->in_capacity = TRACE_WRITER_BUF_SIZE;
    tw->in_buf = (uint8_t *)malloc(tw->in_capacity);
    tw->in_pos = 0;

    tw->out_capacity = ZSTD_CStreamOutSize();
    tw->out_buf = (uint8_t *)malloc(tw->out_capacity);

    tw->records_written = 0;
    tw->uncompressed_bytes_written = 0;
    return tw;
}

/*
 * Flush the input buffer through Zstd compression to the output file.
 * Returns 0 on success, -1 on error.
 */
static inline int trace_writer_flush(TraceWriter *tw)
{
    if (tw->in_pos == 0) {
        return 0;
    }

    if (tw->raw) {
        if (fwrite(tw->in_buf, 1, tw->in_pos, tw->fp) != tw->in_pos) {
            return -1;
        }
        tw->in_pos = 0;
        return 0;
    }

    ZSTD_inBuffer input = { tw->in_buf, tw->in_pos, 0 };

    while (input.pos < input.size) {
        ZSTD_outBuffer output = { tw->out_buf, tw->out_capacity, 0 };
        size_t ret = ZSTD_compressStream2(tw->cstream, &output, &input,
                                          ZSTD_e_continue);
        if (ZSTD_isError(ret)) {
            return -1;
        }
        if (output.pos > 0) {
            if (fwrite(tw->out_buf, 1, output.pos, tw->fp) != output.pos) {
                return -1;
            }
        }
    }

    tw->in_pos = 0;
    return 0;
}

/*
 * Write a single TraceInstructionC record.
 * Returns 0 on success, -1 on error.
 */
static inline int trace_writer_write(TraceWriter *tw,
                                     const struct TraceInstructionC *rec)
{
    if (tw->in_pos + sizeof(*rec) > tw->in_capacity) {
        if (trace_writer_flush(tw) < 0) {
            return -1;
        }
    }

    trace_instruction_write_le(tw->in_buf + tw->in_pos, rec);
    tw->in_pos += sizeof(*rec);
    tw->records_written++;
    tw->uncompressed_bytes_written += sizeof(*rec);
    return 0;
}

/*
 * Close the writer: flush remaining data, finalize compression, close file.
 * Returns 0 on success, -1 on error.
 */
static inline int trace_writer_close(TraceWriter *tw)
{
    int result = 0;

    /* Flush any remaining input data */
    if (trace_writer_flush(tw) < 0) {
        result = -1;
    }

    /* End the Zstd stream, draining all buffered footer output. */
    while (!tw->raw && result == 0) {
        ZSTD_outBuffer output = { tw->out_buf, tw->out_capacity, 0 };
        ZSTD_inBuffer input = { NULL, 0, 0 };
        size_t ret = ZSTD_compressStream2(tw->cstream, &output, &input,
                                          ZSTD_e_end);

        if (ZSTD_isError(ret)) {
            result = -1;
            break;
        }
        if (output.pos > 0 &&
            fwrite(tw->out_buf, 1, output.pos, tw->fp) != output.pos) {
            result = -1;
            break;
        }
        if (ret == 0) {
            break;
        }
    }

    if (tw->cstream) {
        ZSTD_freeCStream(tw->cstream);
    }
    if (fclose(tw->fp) != 0) {
        result = -1;
    }
    free(tw->in_buf);
    free(tw->out_buf);
    free(tw);
    return result;
}

#endif /* TRACE_WRITER_H */
