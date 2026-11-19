#include "qemu/osdep.h"

#include "contrib/plugins/plugin_icount_range.h"

static int parse_nonnegative_u64(const char *name,
                                 const char *value,
                                 uint64_t *out,
                                 char **errp)
{
    char *endptr = NULL;
    unsigned long long parsed;

    if (!value || *value == '\0') {
        *errp = g_strdup_printf("%s requires a value", name);
        return -1;
    }

    if (strchr(value, '-') != NULL) {
        *errp = g_strdup_printf("%s must be a non-negative integer: '%s'",
                                name, value);
        return -1;
    }

    errno = 0;
    parsed = g_ascii_strtoull(value, &endptr, 0);
    if (errno != 0 || endptr == value || (endptr && *endptr != '\0')) {
        *errp = g_strdup_printf("%s must be a non-negative integer: '%s'",
                                name, value);
        return -1;
    }

    *out = (uint64_t)parsed;
    return 0;
}

void plugin_icount_range_parse_state_init(PluginIcountRangeParseState *state)
{
    memset(state, 0, sizeof(*state));
}

PluginIcountRangeParseResult plugin_icount_range_parse_option(
    PluginIcountRangeParseState *state,
    const char *name,
    const char *value,
    char **errp)
{
    uint64_t parsed;

    if (g_strcmp0(name, "start_icount") == 0) {
        if (state->seen_start) {
            *errp = g_strdup("start_icount specified more than once");
            return PLUGIN_ICOUNT_RANGE_PARSE_ERROR;
        }
        if (parse_nonnegative_u64(name, value, &parsed, errp) < 0) {
            return PLUGIN_ICOUNT_RANGE_PARSE_ERROR;
        }
        state->seen_start = true;
        state->start_icount = parsed;
        return PLUGIN_ICOUNT_RANGE_PARSE_HANDLED;
    }

    if (g_strcmp0(name, "end_icount") == 0) {
        if (state->seen_end) {
            *errp = g_strdup("end_icount specified more than once");
            return PLUGIN_ICOUNT_RANGE_PARSE_ERROR;
        }
        if (parse_nonnegative_u64(name, value, &parsed, errp) < 0) {
            return PLUGIN_ICOUNT_RANGE_PARSE_ERROR;
        }
        state->seen_end = true;
        state->end_icount = parsed;
        return PLUGIN_ICOUNT_RANGE_PARSE_HANDLED;
    }

    if (g_strcmp0(name, "skip_icount") == 0) {
        if (state->seen_skip) {
            *errp = g_strdup("skip_icount specified more than once");
            return PLUGIN_ICOUNT_RANGE_PARSE_ERROR;
        }
        if (parse_nonnegative_u64(name, value, &parsed, errp) < 0) {
            return PLUGIN_ICOUNT_RANGE_PARSE_ERROR;
        }
        state->seen_skip = true;
        state->skip_icount = parsed;
        return PLUGIN_ICOUNT_RANGE_PARSE_HANDLED;
    }

    if (g_strcmp0(name, "trace_icount") == 0) {
        if (state->seen_trace) {
            *errp = g_strdup("trace_icount specified more than once");
            return PLUGIN_ICOUNT_RANGE_PARSE_ERROR;
        }
        if (parse_nonnegative_u64(name, value, &parsed, errp) < 0) {
            return PLUGIN_ICOUNT_RANGE_PARSE_ERROR;
        }
        state->seen_trace = true;
        state->trace_icount = parsed;
        return PLUGIN_ICOUNT_RANGE_PARSE_HANDLED;
    }

    return PLUGIN_ICOUNT_RANGE_PARSE_UNHANDLED;
}

int plugin_icount_range_finalize(const PluginIcountRangeParseState *state,
                                 PluginIcountRange *range,
                                 char **errp)
{
    const bool has_abs = state->seen_start || state->seen_end;
    const bool has_rel = state->seen_skip || state->seen_trace;

    memset(range, 0, sizeof(*range));

    if (!has_abs && !has_rel) {
        return 0;
    }

    if (has_abs && has_rel) {
        *errp = g_strdup("start/end and skip/trace interval options cannot be mixed");
        return -1;
    }

    if (has_abs) {
        if (!state->seen_start || !state->seen_end) {
            *errp = g_strdup("start_icount and end_icount must be provided together");
            return -1;
        }
        if (state->start_icount >= state->end_icount) {
            *errp = g_strdup("start_icount must be smaller than end_icount");
            return -1;
        }

        range->enabled = true;
        range->start_icount = state->start_icount;
        range->end_icount = state->end_icount;
        return 0;
    }

    if (!state->seen_skip || !state->seen_trace) {
        *errp = g_strdup("skip_icount and trace_icount must be provided together");
        return -1;
    }
    if (state->trace_icount == 0) {
        *errp = g_strdup("trace_icount must be greater than zero");
        return -1;
    }
    if (UINT64_MAX - state->skip_icount < state->trace_icount) {
        *errp = g_strdup("skip_icount + trace_icount overflows uint64_t");
        return -1;
    }

    range->enabled = true;
    range->start_icount = state->skip_icount;
    range->end_icount = state->skip_icount + state->trace_icount;
    return 0;
}

bool plugin_icount_range_has_any_option(
    const PluginIcountRangeParseState *state)
{
    return state->seen_start || state->seen_end ||
           state->seen_skip || state->seen_trace;
}

bool plugin_icount_range_contains_exec(const PluginIcountRange *range,
                                       uint64_t exec_count)
{
    if (!range->enabled) {
        return true;
    }

    return exec_count > range->start_icount &&
           exec_count <= range->end_icount;
}

bool plugin_icount_range_before_exec(const PluginIcountRange *range,
                                     uint64_t exec_count)
{
    if (!range->enabled) {
        return false;
    }

    return exec_count <= range->start_icount;
}

bool plugin_icount_range_after_exec(const PluginIcountRange *range,
                                    uint64_t exec_count)
{
    if (!range->enabled) {
        return false;
    }

    return exec_count > range->end_icount;
}
