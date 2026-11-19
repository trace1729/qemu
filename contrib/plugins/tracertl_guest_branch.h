#ifndef TRACERTL_GUEST_BRANCH_H
#define TRACERTL_GUEST_BRANCH_H

#include <stddef.h>
#include <stdint.h>

uint32_t tracertl_guest_ldl_le_p(const uint8_t *bytes, size_t len);
uint8_t tracertl_aarch64_branch_type(const uint8_t *bytes, size_t len);

#endif
