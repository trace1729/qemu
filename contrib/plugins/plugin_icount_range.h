#ifndef PLUGIN_ICOUNT_RANGE_H
#define PLUGIN_ICOUNT_RANGE_H

#include <stdbool.h>
#include <stdint.h>

typedef struct PluginIcountRange {
    bool enabled;
    uint64_t start_icount;
    uint64_t end_icount;
} PluginIcountRange;

typedef struct PluginIcountRangeParseState {
    bool seen_start;
    bool seen_end;
    bool seen_skip;
    bool seen_trace;
    uint64_t start_icount;
    uint64_t end_icount;
    uint64_t skip_icount;
    uint64_t trace_icount;
} PluginIcountRangeParseState;

typedef enum PluginIcountRangeParseResult {
    PLUGIN_ICOUNT_RANGE_PARSE_UNHANDLED = 0,
    PLUGIN_ICOUNT_RANGE_PARSE_HANDLED = 1,
    PLUGIN_ICOUNT_RANGE_PARSE_ERROR = -1,
} PluginIcountRangeParseResult;

void plugin_icount_range_parse_state_init(PluginIcountRangeParseState *state);

PluginIcountRangeParseResult plugin_icount_range_parse_option(
    PluginIcountRangeParseState *state,
    const char *name,
    const char *value,
    char **errp);

int plugin_icount_range_finalize(const PluginIcountRangeParseState *state,
                                 PluginIcountRange *range,
                                 char **errp);

bool plugin_icount_range_has_any_option(
    const PluginIcountRangeParseState *state);

bool plugin_icount_range_contains_exec(const PluginIcountRange *range,
                                       uint64_t exec_count);

bool plugin_icount_range_before_exec(const PluginIcountRange *range,
                                     uint64_t exec_count);

bool plugin_icount_range_after_exec(const PluginIcountRange *range,
                                    uint64_t exec_count);

#endif /* PLUGIN_ICOUNT_RANGE_H */
