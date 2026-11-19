/*
 * Focused regression test for TraceWriter zstd finalization.
 */
#include "qemu/osdep.h"
#include "contrib/plugins/trace_writer.h"

static uint32_t load_u32_le(const uint8_t *src)
{
    return src[0] |
           ((uint32_t)src[1] << 8) |
           ((uint32_t)src[2] << 16) |
           ((uint32_t)src[3] << 24);
}

static uint64_t load_u64_le(const uint8_t *src)
{
    return (uint64_t)load_u32_le(src) |
           ((uint64_t)load_u32_le(src + 4) << 32);
}

static void write_sample_record(struct TraceInstructionC *rec, uint64_t base)
{
    trace_instruction_init(rec);
    rec->instr_pc_va = base + 1;
    rec->instr_pc_pa = base + 2;
    rec->exu_data.arthi_src.src0 = base + 3;
    rec->exu_data.arthi_src.src1 = base + 4;
    rec->target = base + 5;
    rec->instr = (uint32_t)(base + 6);
    trace_set_memory_type_size(rec, TRACE_MEM_TYPE_LOAD, 4);
    rec->branch_type = (uint8_t)(base + 7);
    rec->branch_taken = (uint8_t)(base + 8);
    rec->exception = (uint8_t)(base + 9);
}

static void pack_records_le(uint8_t *dst,
                            const struct TraceInstructionC *recs,
                            size_t n_recs)
{
    for (size_t i = 0; i < n_recs; i++) {
        trace_instruction_write_le(dst + i * sizeof(recs[0]), &recs[i]);
    }
}

static void test_close_drains_zstd_footer(void)
{
    g_autofree char *path = NULL;
    struct TraceInstructionC recs[8];
    uint8_t expected[sizeof(recs)];
    g_autofree char *compressed = NULL;
    gsize compressed_len = 0;
    GByteArray *decoded;
    int fd;
    TraceWriter *tw;
    ZSTD_DCtx *dctx;
    ZSTD_inBuffer input;
    size_t ret = 1;
    size_t i;

    fd = g_file_open_tmp("tracertl-trace-writer-XXXXXX.zst", &path, NULL);
    g_assert_cmpint(fd, >=, 0);
    close(fd);

    tw = trace_writer_open(path, 1);
    g_assert_nonnull(tw);

    tw->out_capacity = 1;
    tw->out_buf = g_realloc(tw->out_buf, tw->out_capacity);

    for (i = 0; i < G_N_ELEMENTS(recs); i++) {
        write_sample_record(&recs[i], i * 16);
        g_assert_cmpint(trace_writer_write(tw, &recs[i]), ==, 0);
    }
    pack_records_le(expected, recs, G_N_ELEMENTS(recs));

    g_assert_cmpint(trace_writer_close(tw), ==, 0);
    g_assert_true(g_file_get_contents(path, &compressed, &compressed_len, NULL));

    dctx = ZSTD_createDCtx();
    g_assert_nonnull(dctx);
    decoded = g_byte_array_new();
    input = (ZSTD_inBuffer){ compressed, compressed_len, 0 };

    while (input.pos < input.size && ret != 0) {
        uint8_t out[32];
        ZSTD_outBuffer output = { out, sizeof(out), 0 };

        ret = ZSTD_decompressStream(dctx, &output, &input);
        g_assert_false(ZSTD_isError(ret));
        g_byte_array_append(decoded, out, output.pos);
    }

    g_assert_cmpuint(input.pos, ==, input.size);
    g_assert_cmpuint(ret, ==, 0);
    g_assert_cmpuint(decoded->len, ==, sizeof(recs));
    g_assert_cmpmem(decoded->data, decoded->len, expected, sizeof(expected));

    g_byte_array_unref(decoded);
    ZSTD_freeDCtx(dctx);
    unlink(path);
}

static void test_record_bytes_are_little_endian(void)
{
    struct TraceInstructionC rec;
    uint8_t packed[sizeof(rec)];

    write_sample_record(&rec, UINT64_C(0x0102030405060708));
    trace_instruction_write_le(packed, &rec);

    g_assert_cmphex(load_u64_le(packed + 0), ==, rec.instr_pc_va);
    g_assert_cmphex(load_u64_le(packed + 8), ==, rec.instr_pc_pa);
    g_assert_cmphex(load_u64_le(packed + 16), ==, rec.exu_data.arthi_src.src0);
    g_assert_cmphex(load_u64_le(packed + 24), ==, rec.exu_data.arthi_src.src1);
    g_assert_cmphex(load_u64_le(packed + 32), ==, rec.target);
    g_assert_cmphex(load_u32_le(packed + 40), ==, rec.instr);
    g_assert_cmphex(packed[44], ==, rec.memory_type_and_size);
    g_assert_cmphex(packed[45], ==, rec.branch_type);
    g_assert_cmphex(packed[46], ==, rec.branch_taken);
    g_assert_cmphex(packed[47], ==, rec.exception);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/tracertl/trace-writer/record-bytes-little-endian",
                    test_record_bytes_are_little_endian);
    g_test_add_func("/tracertl/trace-writer/close-drains-zstd-footer",
                    test_close_drains_zstd_footer);
    return g_test_run();
}
