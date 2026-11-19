/*
 * Focused regression tests for shared plugin icount-range parsing.
 */
#include "qemu/osdep.h"
#include "contrib/plugins/plugin_icount_range.h"

static void test_finalize_start_end_range(void)
{
    PluginIcountRangeParseState state;
    PluginIcountRange range;
    char *err = NULL;

    plugin_icount_range_parse_state_init(&state);
    g_assert_cmpint(plugin_icount_range_parse_option(&state, "start_icount",
                                                     "12", &err),
                    ==, PLUGIN_ICOUNT_RANGE_PARSE_HANDLED);
    g_assert_null(err);
    g_assert_cmpint(plugin_icount_range_parse_option(&state, "end_icount",
                                                     "34", &err),
                    ==, PLUGIN_ICOUNT_RANGE_PARSE_HANDLED);
    g_assert_null(err);
    g_assert_cmpint(plugin_icount_range_finalize(&state, &range, &err), ==, 0);
    g_assert_null(err);
    g_assert_true(range.enabled);
    g_assert_cmpuint(range.start_icount, ==, 12);
    g_assert_cmpuint(range.end_icount, ==, 34);
}

static void test_finalize_skip_trace_range(void)
{
    PluginIcountRangeParseState state;
    PluginIcountRange range;
    char *err = NULL;

    plugin_icount_range_parse_state_init(&state);
    g_assert_cmpint(plugin_icount_range_parse_option(&state, "skip_icount",
                                                     "100", &err),
                    ==, PLUGIN_ICOUNT_RANGE_PARSE_HANDLED);
    g_assert_null(err);
    g_assert_cmpint(plugin_icount_range_parse_option(&state, "trace_icount",
                                                     "25", &err),
                    ==, PLUGIN_ICOUNT_RANGE_PARSE_HANDLED);
    g_assert_null(err);
    g_assert_cmpint(plugin_icount_range_finalize(&state, &range, &err), ==, 0);
    g_assert_null(err);
    g_assert_true(range.enabled);
    g_assert_cmpuint(range.start_icount, ==, 100);
    g_assert_cmpuint(range.end_icount, ==, 125);
}

static void test_finalize_rejects_mixed_forms(void)
{
    PluginIcountRangeParseState state;
    PluginIcountRange range;
    char *err = NULL;

    plugin_icount_range_parse_state_init(&state);
    g_assert_cmpint(plugin_icount_range_parse_option(&state, "start_icount",
                                                     "1", &err),
                    ==, PLUGIN_ICOUNT_RANGE_PARSE_HANDLED);
    g_assert_null(err);
    g_assert_cmpint(plugin_icount_range_parse_option(&state, "trace_icount",
                                                     "5", &err),
                    ==, PLUGIN_ICOUNT_RANGE_PARSE_HANDLED);
    g_assert_null(err);
    g_assert_cmpint(plugin_icount_range_finalize(&state, &range, &err), ==, -1);
    g_assert_nonnull(err);
    g_free(err);
}

static void test_finalize_requires_complete_pair(void)
{
    PluginIcountRangeParseState state;
    PluginIcountRange range;
    char *err = NULL;

    plugin_icount_range_parse_state_init(&state);
    g_assert_cmpint(plugin_icount_range_parse_option(&state, "start_icount",
                                                     "1", &err),
                    ==, PLUGIN_ICOUNT_RANGE_PARSE_HANDLED);
    g_assert_null(err);
    g_assert_cmpint(plugin_icount_range_finalize(&state, &range, &err), ==, -1);
    g_assert_nonnull(err);
    g_free(err);
}

static void test_finalize_rejects_overflow(void)
{
    PluginIcountRangeParseState state;
    PluginIcountRange range;
    char *err = NULL;

    plugin_icount_range_parse_state_init(&state);
    g_assert_cmpint(plugin_icount_range_parse_option(&state, "skip_icount",
                                                     "18446744073709551610",
                                                     &err),
                    ==, PLUGIN_ICOUNT_RANGE_PARSE_HANDLED);
    g_assert_null(err);
    g_assert_cmpint(plugin_icount_range_parse_option(&state, "trace_icount",
                                                     "10", &err),
                    ==, PLUGIN_ICOUNT_RANGE_PARSE_HANDLED);
    g_assert_null(err);
    g_assert_cmpint(plugin_icount_range_finalize(&state, &range, &err), ==, -1);
    g_assert_nonnull(err);
    g_free(err);
}

static void test_exec_membership_uses_half_open_interval(void)
{
    PluginIcountRange range = {
        .enabled = true,
        .start_icount = 10,
        .end_icount = 13,
    };

    g_assert_false(plugin_icount_range_contains_exec(&range, 10));
    g_assert_true(plugin_icount_range_contains_exec(&range, 11));
    g_assert_true(plugin_icount_range_contains_exec(&range, 13));
    g_assert_false(plugin_icount_range_contains_exec(&range, 14));

    g_assert_true(plugin_icount_range_before_exec(&range, 10));
    g_assert_false(plugin_icount_range_before_exec(&range, 11));
    g_assert_false(plugin_icount_range_after_exec(&range, 13));
    g_assert_true(plugin_icount_range_after_exec(&range, 14));
}

static void test_unhandled_option_is_reported(void)
{
    PluginIcountRangeParseState state;
    char *err = NULL;

    plugin_icount_range_parse_state_init(&state);
    g_assert_cmpint(plugin_icount_range_parse_option(&state, "output",
                                                     "trace.zst", &err),
                    ==, PLUGIN_ICOUNT_RANGE_PARSE_UNHANDLED);
    g_assert_null(err);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/plugin-icount-range/finalize-start-end",
                    test_finalize_start_end_range);
    g_test_add_func("/plugin-icount-range/finalize-skip-trace",
                    test_finalize_skip_trace_range);
    g_test_add_func("/plugin-icount-range/finalize-rejects-mixed-forms",
                    test_finalize_rejects_mixed_forms);
    g_test_add_func("/plugin-icount-range/finalize-requires-complete-pair",
                    test_finalize_requires_complete_pair);
    g_test_add_func("/plugin-icount-range/finalize-rejects-overflow",
                    test_finalize_rejects_overflow);
    g_test_add_func("/plugin-icount-range/exec-membership-half-open",
                    test_exec_membership_uses_half_open_interval);
    g_test_add_func("/plugin-icount-range/unhandled-option",
                    test_unhandled_option_is_reported);

    return g_test_run();
}
