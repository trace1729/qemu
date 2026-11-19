#include "qemu/osdep.h"
#include "contrib/plugins/tracertl_guest_branch.h"

uint32_t tracertl_guest_ldl_le_p(const uint8_t *bytes, size_t len)
{
    if (!bytes) {
        return 0U;
    }

    switch (len) {
    case 0:
        return 0U;
    case 1:
        return bytes[0];
    case 2:
        return bytes[0] | ((uint32_t)bytes[1] << 8);
    case 3:
        return bytes[0] |
               ((uint32_t)bytes[1] << 8) |
               ((uint32_t)bytes[2] << 16);
    default:
        return bytes[0] |
               ((uint32_t)bytes[1] << 8) |
               ((uint32_t)bytes[2] << 16) |
               ((uint32_t)bytes[3] << 24);
    }
}

uint8_t tracertl_aarch64_branch_type(const uint8_t *bytes, size_t len)
{
    uint32_t insn = tracertl_guest_ldl_le_p(bytes, len);

    if (len < sizeof(insn)) {
        return 0;
    }

    switch (insn & 0xfc000000U) {
    case 0x14000000U: /* B imm26 */
    case 0x94000000U: /* BL imm26 */
        return 2;
    }

    switch (insn & 0xff000010U) {
    case 0x54000000U: /* B.cond imm19 */
        return 1;
    }

    switch (insn & 0x7e000000U) {
    case 0x34000000U: /* CBZ */
    case 0x35000000U: /* CBNZ */
    case 0x36000000U: /* TBZ */
    case 0x37000000U: /* TBNZ */
        return 1;
    }

    switch (insn & 0xfffffc1fU) {
    case 0xd61f0000U: /* BR */
    case 0xd63f0000U: /* BLR */
    case 0xd65f0000U: /* RET */
    case 0xd69f0000U: /* ERET */
        return 3;
    }

    return 0;
}
