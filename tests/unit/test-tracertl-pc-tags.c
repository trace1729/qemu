/*
 * Focused regression test for TracerTL synthetic trace-PC sidecars.
 */
#include "qemu/osdep.h"
#include "contrib/plugins/tracertl_pc_tag_sidecar.h"

static void test_pc_tag_name_strings(void)
{
    g_assert_cmpstr(tracertl_pc_tag_name(QEMU_PLUGIN_RV_TAG_NONE),
                    ==, "none");
    g_assert_cmpstr(tracertl_pc_tag_name(QEMU_PLUGIN_RV_TAG_MOVCOND),
                    ==, "movcond");
    g_assert_cmpstr(tracertl_pc_tag_name(QEMU_PLUGIN_RV_TAG_HELPER_PLACEHOLDER),
                    ==, "helper_placeholder");
    g_assert_cmpstr(tracertl_pc_tag_name(QEMU_PLUGIN_RV_TAG_INDIRECT_BRANCH_PLACEHOLDER),
                    ==, "indirect_branch_placeholder");
    g_assert_cmpstr(tracertl_pc_tag_name(QEMU_PLUGIN_RV_TAG_GENERIC_DEPENDENCY_PLACEHOLDER),
                    ==, "generic_dependency_placeholder");
}

static void test_sidecar_coalesces_and_deduplicates(void)
{
    g_autofree char *path = NULL;
    g_autofree char *contents = NULL;
    TracertlPcTagSidecarWriter *writer;
    int fd;

    fd = g_file_open_tmp("tracertl-pc-tags-XXXXXX.csv", &path, NULL);
    g_assert_cmpint(fd, >=, 0);
    close(fd);

    writer = tracertl_pc_tag_sidecar_open(path);
    g_assert_nonnull(writer);

    g_assert_cmpint(tracertl_pc_tag_sidecar_note(writer, 0x1000,
                                                 QEMU_PLUGIN_RV_TAG_MOVCOND),
                    ==, 0);
    g_assert_cmpint(tracertl_pc_tag_sidecar_note(writer, 0x1004,
                                                 QEMU_PLUGIN_RV_TAG_MOVCOND),
                    ==, 0);
    g_assert_cmpint(tracertl_pc_tag_sidecar_note(writer, 0x1004,
                                                 QEMU_PLUGIN_RV_TAG_MOVCOND),
                    ==, 0);
    g_assert_cmpint(tracertl_pc_tag_sidecar_note(writer, 0x1008,
                                                 QEMU_PLUGIN_RV_TAG_HELPER_PLACEHOLDER),
                    ==, 0);
    g_assert_cmpint(tracertl_pc_tag_sidecar_note(writer, 0x2000,
                                                 QEMU_PLUGIN_RV_TAG_NONE),
                    ==, 0);
    g_assert_cmpint(tracertl_pc_tag_sidecar_close(writer), ==, 0);

    g_assert_true(g_file_get_contents(path, &contents, NULL, NULL));
    g_assert_cmpstr(contents, ==,
                    "# trace_pc_start,trace_pc_end,tag\n"
                    "# sidecar_mode=ordinal\n"
                    "0x1000,0x1008,movcond\n"
                    "0x1008,0x100c,helper_placeholder\n");

    unlink(path);
}

static void test_sidecar_rejects_conflicting_duplicate_pc(void)
{
    g_autofree char *path = NULL;
    TracertlPcTagSidecarWriter *writer;
    int fd;

    fd = g_file_open_tmp("tracertl-pc-tags-conflict-XXXXXX.csv", &path, NULL);
    g_assert_cmpint(fd, >=, 0);
    close(fd);

    writer = tracertl_pc_tag_sidecar_open(path);
    g_assert_nonnull(writer);

    g_assert_cmpint(tracertl_pc_tag_sidecar_note(writer, 0x3000,
                                                 QEMU_PLUGIN_RV_TAG_MOVCOND),
                    ==, 0);
    g_assert_cmpint(tracertl_pc_tag_sidecar_note(writer, 0x3000,
                                                 QEMU_PLUGIN_RV_TAG_INDIRECT_BRANCH_PLACEHOLDER),
                    ==, -1);
    g_assert_cmpint(tracertl_pc_tag_sidecar_close(writer), ==, -1);
    unlink(path);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/tracertl/pc-tags/name-strings",
                    test_pc_tag_name_strings);
    g_test_add_func("/tracertl/pc-tags/coalesces-and-deduplicates",
                    test_sidecar_coalesces_and_deduplicates);
    g_test_add_func("/tracertl/pc-tags/conflicting-duplicate-pc",
                    test_sidecar_rejects_conflicting_duplicate_pc);
    return g_test_run();
}
