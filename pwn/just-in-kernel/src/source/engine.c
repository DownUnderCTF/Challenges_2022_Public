#include "challenge_module.h"

int exec_user_data(char* user_data)
{
    unsigned char* map;
    unsigned long long map_base;
    size_t len = 0;
    int (*entry_point)(void);

    /* parse instructions */
    instruction_t instructions[MAX_INSTRUCTIONS];
    if (!instructions_parse(instructions, user_data, &len)) {
        return 0;
    }

    /* map executable memory */
    map = (unsigned char*)__vmalloc(0x1000, GFP_KERNEL, PAGE_KERNEL_EXEC);
    if (map == NULL) {
        return 0;
    }
    map_base = (unsigned long long)map;

    /* compile instructions */
    if (!compile_instructions(instructions, map, len, map_base)) {
        return 0;
    }

    /* call compiled code */
    entry_point = (void*)map_base;
    entry_point();

    return 1;
}
