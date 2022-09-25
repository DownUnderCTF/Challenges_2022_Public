#include "challenge_module.h"

#define MVE_SIZE 10
#define ADD_SIZE 2
#define CMP_SIZE 2
#define JMP_SIZE 12

typedef union {
    unsigned long long value;
    char               bytes[8];
} uint64_data_t;

static unsigned char reg_mve[5][2] = {
    { 0x00, 0x00 },
    { 0x48, 0xb8 },
    { 0x48, 0xbb },
    { 0x48, 0xb9 },
    { 0x48, 0xba }
};

static unsigned char reg_add[5][5] = {
    { 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0xc0, 0xd8, 0xc8, 0xd0 },
    { 0x00, 0xc3, 0xdb, 0xcb, 0xd3 },
    { 0x00, 0xc1, 0xd9, 0xc9, 0xd1 },
    { 0x00, 0xc2, 0xda, 0xca, 0xd2 }
};

static unsigned char reg_cmp[5][5] = {
    { 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0xc0, 0xd8, 0xc8, 0xd0 },
    { 0x00, 0xc3, 0xdb, 0xcb, 0xd3 },
    { 0x00, 0xc1, 0xd9, 0xc9, 0xd1 },
    { 0x00, 0xc2, 0xda, 0xca, 0xd2 }
};

int compile_mve(instruction_t instruction, unsigned char* buf)
{
    unsigned char data[MVE_SIZE] = {};
    uint64_data_t source;
    size_t i;

    /* check that first operand is a register, and second operand is a value */
    if (!(instruction.operands[0] & 1) || instruction.operands[1] & 1) {
        return 0;
    }

    /* retrieve 64-bit `movabs` prefix byte */
    memcpy(data, reg_mve[instruction.operands[0] >> 1], 2);

    /* compile value to store in register */
    source.value = (operand_t)(instruction.operands[1] >> 1);
    for (i = 2; i < MVE_SIZE; ++i) {
        data[i] = source.bytes[i-2] & 0xff;
    }

    memcpy(buf, data, MVE_SIZE);
    return 1;
}

int compile_add(instruction_t instruction, unsigned char* buf)
{
    unsigned char data[ADD_SIZE] = { 0x01 };

    /* check that both operands are registers */
    if (!(instruction.operands[0] & 1) || !(instruction.operands[1] & 1)) {
        return 0;
    }

    /* retrieve corresponding add instruction */
    data[1] = reg_add[instruction.operands[0] >> 1][instruction.operands[1] >> 1];

    memcpy(buf, data, ADD_SIZE);
    return 1;
}

int compile_cmp(instruction_t instruction, unsigned char* buf)
{
    unsigned char data[CMP_SIZE] = { 0x39 };

    /* check that both operands are registers */
    if (!(instruction.operands[0] & 1) || !(instruction.operands[1] & 1)) {
        return 0;
    }

    /* retrieve corresponding cmp instruction */
    data[1] = reg_cmp[instruction.operands[0] >> 1][instruction.operands[1] >> 1];

    memcpy(buf, data, CMP_SIZE);
    return 1;
}

int compile_jmp(instruction_t instruction, unsigned char* buf,
        unsigned long long base)
{
    unsigned long long addr;
    unsigned char data[JMP_SIZE] = { 0x48, 0xbf };
    uint64_data_t addr_data;
    size_t i;

    /* check that first operand is a value, and second operand is zero */
    if (instruction.operands[0] & 1 || instruction.operands[1] != 0) {
        return 0;
    }

    /* calculate jump address */
    addr = base + (instruction.operands[0] >> 1);
    addr_data.value = addr;

    /* generate `mov rdi, addr` instruction */
    for (i = 2; i < JMP_SIZE - 2; ++i) {
        data[i] = addr_data.bytes[i-2];
    }

    /* generate `jmp rdi` instruction */
    data[JMP_SIZE - 2] = 0xff;
    data[JMP_SIZE - 1] = 0xe7;

    memcpy(buf, data, JMP_SIZE);
    return 1;
}

int compile_instructions(instruction_t* instructions, unsigned char* buf,
        size_t len, unsigned long long base)
{
    size_t i;

    for (i = 0; i < len; ++i) {
        if (instructions[i].mnemonic == MNEMONIC_MVE) {
            if (!compile_mve(instructions[i], buf)) {
                return 0;
            }
            buf += MVE_SIZE;
        }
        else if (instructions[i].mnemonic == MNEMONIC_ADD) {
            if (!compile_add(instructions[i], buf)) {
                return 0;
            }
            buf += ADD_SIZE;
        }
        else if (instructions[i].mnemonic == MNEMONIC_CMP) {
            if (!compile_cmp(instructions[i], buf)) {
                return 0;
            }
            buf += CMP_SIZE;
        }
        else if (instructions[i].mnemonic == MNEMONIC_JMP) {
            if (!compile_jmp(instructions[i], buf, base)) {
                return 0;
            }
            buf += JMP_SIZE;
        }
        else {
            /* instruction not implemented */
            return 0;
        }
    }

    /* add `ret` instruction */
    buf[0] = 0xc3;

    return 1;
}
