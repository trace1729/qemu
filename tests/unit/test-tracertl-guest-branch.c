/*
 * Focused regression tests for guest branch classification helpers.
 */
#include "qemu/osdep.h"
#include "contrib/plugins/tracertl_guest_branch.h"

static void test_aarch64_direct_branch_is_classified(void)
{
    static const uint8_t bytes[] = { 0x00, 0x00, 0x00, 0x14 };

    g_assert_cmpuint(tracertl_aarch64_branch_type(bytes, sizeof(bytes)),
                     ==, 2);
}

static void test_aarch64_conditional_branch_is_classified(void)
{
    static const uint8_t bytes[] = { 0x00, 0x00, 0x00, 0x54 };

    g_assert_cmpuint(tracertl_aarch64_branch_type(bytes, sizeof(bytes)),
                     ==, 1);
}

static void test_aarch64_return_is_indirect(void)
{
    static const uint8_t bytes[] = { 0xc0, 0x03, 0x5f, 0xd6 };

    g_assert_cmpuint(tracertl_aarch64_branch_type(bytes, sizeof(bytes)),
                     ==, 3);
}

static void test_aarch64_exception_return_is_indirect(void)
{
    static const uint8_t bytes[] = { 0xe0, 0x03, 0x9f, 0xd6 };

    g_assert_cmpuint(tracertl_aarch64_branch_type(bytes, sizeof(bytes)),
                     ==, 3);
}

static void test_aarch64_non_branch_stays_clear(void)
{
    static const uint8_t bytes[] = { 0x00, 0x00, 0x00, 0x8b };

    g_assert_cmpuint(tracertl_aarch64_branch_type(bytes, sizeof(bytes)),
                     ==, 0);
}

static void test_guest_ldl_le_p_decodes_little_endian_words(void)
{
    static const uint8_t bytes[] = { 0x23, 0x20, 0x00, 0x00 };

    g_assert_cmphex(tracertl_guest_ldl_le_p(bytes, sizeof(bytes)),
                    ==, 0x00002023U);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/tracertl/guest-branch/aarch64-direct",
                    test_aarch64_direct_branch_is_classified);
    g_test_add_func("/tracertl/guest-branch/aarch64-conditional",
                    test_aarch64_conditional_branch_is_classified);
    g_test_add_func("/tracertl/guest-branch/aarch64-return-indirect",
                    test_aarch64_return_is_indirect);
    g_test_add_func("/tracertl/guest-branch/aarch64-exception-return-indirect",
                    test_aarch64_exception_return_is_indirect);
    g_test_add_func("/tracertl/guest-branch/aarch64-non-branch",
                    test_aarch64_non_branch_stays_clear);
    g_test_add_func("/tracertl/guest-branch/ldl-le-p",
                    test_guest_ldl_le_p_decodes_little_endian_words);

    return g_test_run();
}
