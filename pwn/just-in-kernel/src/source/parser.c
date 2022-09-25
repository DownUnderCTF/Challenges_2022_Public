#include "challenge_module.h"

#define MAX_WORDS 3
#define MIN_WORDS 2

typedef enum {
    REG_A = 1,
    REG_B = 2,
    REG_C = 3,
    REG_D = 4
} reg_t;

operand_t operand_from_str(char* str)
{
    operand_t operand = 0;

    /* convert `str` to register enum */
    if (strcmp(str, "a") == 0) {
        return ((operand_t)REG_A << 1) | 1;
    }
    if (strcmp(str, "b") == 0) {
        return ((operand_t)REG_B << 1) | 1;
    }
    if (strcmp(str, "c") == 0) {
        return ((operand_t)REG_C << 1) | 1;
    }
    if (strcmp(str, "d") == 0) {
        return ((operand_t)REG_D << 1) | 1;
    }

    /* if operand doesn't match register, parse as integer */
    if (kstrtoull(str, 10, &operand)) {
        return 0;
    }
    return ((operand_t)operand << 1);
}

mnemonic_t mnemonic_from_str(char* str)
{
    /* convert `str` to mnemonic enum */
    if (strcmp(str, "mve") == 0) {
        return MNEMONIC_MVE;
    }
    if (strcmp(str, "add") == 0) {
        return MNEMONIC_ADD;
    }
    if (strcmp(str, "cmp") == 0) {
        return MNEMONIC_CMP;
    }
    if (strcmp(str, "jmp") == 0) {
        return MNEMONIC_JMP;
    }
    if (strcmp(str, "jeq") == 0) {
        return MNEMONIC_JEQ;
    }
    if (strcmp(str, "jgt") == 0) {
        return MNEMONIC_JGT;
    }
    if (strcmp(str, "jlt") == 0) {
        return MNEMONIC_JLT;
    }

    /* if mnemonic doesn't match, return invalid */
    return MNEMONIC_BAD;
}

int instruction_from_str(instruction_t* instruction, char* line)
{
    char* raw_word;
    char* words[MAX_WORDS];
    size_t num_words, i;

    /* parse mnemonic string */
    raw_word = strsep(&line, " ");
    if (raw_word == NULL) {
        return 0;
    }
    words[0] = raw_word;

    /* parse operand strings */ 
    num_words = 1;
    while ((raw_word = strsep(&line, " ")) != NULL) {
        if (num_words >= MAX_WORDS) {
            break;
        }
        words[num_words++] = raw_word;
    }
    if (num_words < MIN_WORDS) {
        return 0;
    }

    /* parse mnemonic and operands */
    instruction->mnemonic = mnemonic_from_str(words[0]);
    if (instruction->mnemonic == MNEMONIC_BAD) {
        return 0;
    }
    for (i = 1; i < num_words; ++i) {
        instruction->operands[i-1] = operand_from_str(words[i]);
    }

    if (num_words < 3) {
        instruction->operands[1] = 0;
    }

    if (instruction->mnemonic == MNEMONIC_JMP) {
        /* jmp instruction can't be to register */
        if (instruction->operands[0] & 1) {
            return 0;
        }

        /* jmp can't be greater that 0xfff */
        instruction->operands[0] = ((instruction->operands[0] >> 1) & 0xfff) << 1;
    }

    return 1;
}

int instructions_parse(instruction_t* instructions, char* user_data,
        size_t* len)
{
    char* raw_line;
    char* lines[MAX_INSTRUCTIONS];
    size_t num_lines, i;

    /* retrieve and store first line */
    raw_line = strsep(&user_data, "\n");
    if (raw_line == NULL) {
        return 0;
    }
    lines[0] = raw_line;

    /* retrieve and store the rest of the lines */
    num_lines = 1;
    while ((raw_line = strsep(&user_data, "\n")) != NULL) {
        if (num_lines >= MAX_INSTRUCTIONS) {
            break;
        }
        lines[num_lines++] = raw_line;
    }

    /* convert lines into instructions */
    for (i = 0; i < num_lines; ++i) {
        instruction_t instruction;
        if (!instruction_from_str(&instruction, lines[i])) {
            return 0;
        }
        instructions[i] = instruction;
    }

    *len = num_lines;
    return 1;
}
