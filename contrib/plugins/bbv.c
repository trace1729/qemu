/*
 * Generate basic block vectors for use with the SimPoint analysis tool.
 * SimPoint: https://cseweb.ucsd.edu/~calder/simpoint/
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <pthread.h>
#include <glib.h>

#include <qemu-plugin.h>

typedef struct Bb {
    uint64_t vaddr;
    struct qemu_plugin_scoreboard *count;
    unsigned int index;
} Bb;

typedef struct Vcpu {
    uint64_t count;
    FILE *file;
    unsigned generation;
    uint64_t windows;
} Vcpu;

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
static GHashTable *bbs;
static GRWLock bbs_lock;
static char *filename;
static struct qemu_plugin_scoreboard *vcpus;
static uint64_t interval = 100000000;

static bool split_threads, fork_child;

static void detach_child(void)
{
    fork_child = true;
}

static void finish_profile(qemu_plugin_id_t id, unsigned index)
{
    if (fork_child) {
        return;
    }
    Vcpu *v = qemu_plugin_scoreboard_find(vcpus, index);
    if (!v->file) {
        return;
    }
    if (fclose(v->file)) {
        g_error("bbv: profile write failed");
    }
    v->file = NULL;
    if (split_threads) {
        g_autofree char *path = g_strdup_printf("%s.t%u.g%u.json", filename, index, v->generation);
        g_autofree char *data = g_strdup_printf("{\"interval\":%" PRIu64 ",\"windows\":%" PRIu64 ",\"tail\":%" PRIu64 "}\n", interval, v->windows, v->count);
        if (!g_file_set_contents(path, data, -1, NULL)) {
            g_error("bbv: failed to save %s", path);
        }
    }
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    if (fork_child) {
        return;
    }
    for (int i = 0; i < qemu_plugin_num_vcpus(); i++) {
        finish_profile(id, i);
    }

    g_hash_table_unref(bbs);
    g_free(filename);
    qemu_plugin_scoreboard_free(vcpus);
}

static void free_bb(void *data)
{
    qemu_plugin_scoreboard_free(((Bb *)data)->count);
    g_free(data);
}

static qemu_plugin_u64 count_u64(void)
{
    return qemu_plugin_scoreboard_u64_in_struct(vcpus, Vcpu, count);
}

static qemu_plugin_u64 bb_count_u64(Bb *bb)
{
    return qemu_plugin_scoreboard_u64(bb->count);
}

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index)
{
    g_autofree gchar *vcpu_filename = NULL;
    Vcpu *vcpu = qemu_plugin_scoreboard_find(vcpus, vcpu_index);

    if (fork_child) {
        return;
    }
    if (split_threads) {
        if (vcpu->generation) {
            GHashTableIter it;
            void *value;
            g_rw_lock_reader_lock(&bbs_lock);
            g_hash_table_iter_init(&it, bbs);
            while (g_hash_table_iter_next(&it, NULL, &value)) {
                qemu_plugin_u64_set(bb_count_u64(value), vcpu_index, 0);
            }
            g_rw_lock_reader_unlock(&bbs_lock);
        }
        vcpu->count = vcpu->windows = 0;
        vcpu_filename = g_strdup_printf("%s.t%u.g%u.bb", filename, vcpu_index, ++vcpu->generation);
        vcpu->file = fopen(vcpu_filename, "wx");
        if (!vcpu->file) {
            g_error("bbv: cannot create %s", vcpu_filename);
        }
        setvbuf(vcpu->file, NULL, _IOFBF, 1024 * 1024);
        return;
    }
    vcpu_filename = g_strdup_printf("%s.%u.bb", filename, vcpu_index);
    vcpu->file = fopen(vcpu_filename, "w");
}

static void vcpu_interval_exec(unsigned int vcpu_index, void *udata)
{
    Vcpu *vcpu = qemu_plugin_scoreboard_find(vcpus, vcpu_index);
    GHashTableIter iter;
    void *value;

    if (!vcpu->file) {
        return;
    }

    if (fork_child) {
        return;
    }

    uint64_t carry = vcpu->count - interval;
    Bb *split_bb = udata;
    if (carry && !split_bb) {
        g_error("bbv: interval boundary has no translation block");
    }

    vcpu->windows++;

    fputc('T', vcpu->file);

    g_rw_lock_reader_lock(&bbs_lock);
    g_hash_table_iter_init(&iter, bbs);

    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        Bb *bb = value;
        uint64_t bb_count = qemu_plugin_u64_get(bb_count_u64(bb), vcpu_index);

        if (bb == split_bb) {
            if (carry > bb_count) {
                g_error("bbv: translation block carry exceeds execution count");
            }
            bb_count -= carry;
        }
        if (!bb_count) {
            continue;
        }

        fprintf(vcpu->file, ":%u:%" PRIu64 " ", bb->index, bb_count);
        qemu_plugin_u64_set(bb_count_u64(bb), vcpu_index, 0);
    }

    g_rw_lock_reader_unlock(&bbs_lock);
    fputc('\n', vcpu->file);
    if (split_bb) {
        qemu_plugin_u64_set(bb_count_u64(split_bb), vcpu_index, carry);
    }
    vcpu->count = carry;
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    uint64_t n_insns = qemu_plugin_tb_n_insns(tb);
    uint64_t vaddr = qemu_plugin_tb_vaddr(tb);
    Bb *bb;

    if (fork_child) {
        return;
    }
    g_rw_lock_writer_lock(&bbs_lock);
    bb = g_hash_table_lookup(bbs, &vaddr);
    if (!bb) {
        bb = g_new(Bb, 1);
        bb->vaddr = vaddr;
        bb->count = qemu_plugin_scoreboard_new(sizeof(uint64_t));
        bb->index = g_hash_table_size(bbs) + 1;
        g_hash_table_replace(bbs, &bb->vaddr, bb);
    }
    g_rw_lock_writer_unlock(&bbs_lock);

    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_ADD_U64, count_u64(), n_insns);

    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_ADD_U64, bb_count_u64(bb), n_insns);

    qemu_plugin_register_vcpu_tb_exec_cond_cb(
        tb, vcpu_interval_exec, QEMU_PLUGIN_CB_NO_REGS,
        QEMU_PLUGIN_COND_GE, count_u64(), interval, bb);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
        if (g_strcmp0(tokens[0], "interval") == 0) {
            interval = g_ascii_strtoull(tokens[1], NULL, 10);
        } else if (!strcmp(opt, "threads=split")) {
            split_threads = true;
        } else if (g_strcmp0(tokens[0], "outfile") == 0) {
            filename = tokens[1];
            tokens[1] = NULL;
        } else {
            fprintf(stderr, "option parsing failed: %s\n", opt);
            return -1;
        }
    }

    if (!filename) {
        fputs("outfile unspecified\n", stderr);
        return -1;
    }

    if (split_threads) {
        if (!interval || info->system_emulation || pthread_atfork(NULL, NULL, detach_child)) {
            return -1;
        }
        qemu_plugin_register_vcpu_exit_cb(id, finish_profile);
    }
    bbs = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, free_bb);
    vcpus = qemu_plugin_scoreboard_new(sizeof(Vcpu));
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);

    return 0;
}
