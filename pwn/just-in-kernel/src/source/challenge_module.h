#ifndef __JIK_CHALLENGE_H_
#define __JIK_CHALLENGE_H_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#define MAX_INSTRUCTIONS 100

typedef enum {
    MNEMONIC_MVE,
    MNEMONIC_ADD,
    MNEMONIC_CMP,
    MNEMONIC_JMP,
    MNEMONIC_JEQ,
    MNEMONIC_JGT,
    MNEMONIC_JLT,
    MNEMONIC_BAD
} mnemonic_t;

typedef unsigned long long operand_t;

typedef struct {
    mnemonic_t mnemonic;
    operand_t  operands[2];
} instruction_t;

int instructions_parse(instruction_t* instructions, char* user_data,
        size_t* len);

int compile_instructions(instruction_t* instructions, unsigned char* buf,
        size_t len, unsigned long long base);

int exec_user_data(char* user_data);

#endif /* __JIK_CHALLENGE_H_ */
