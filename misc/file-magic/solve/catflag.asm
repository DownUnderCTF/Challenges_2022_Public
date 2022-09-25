; https://nathanotterness.com/2021/10/tiny_elf_modernized.html
; nasm -f in -o catflag catflag.asm

[bits 64]

global _start

file_load_va: equ 4096 * 40

db 0x7f, 'E', 'L', 'F'
db 2
db 1
db 1
db 0
dq 0
dw 2
dw 0x3e
dd 1
dq _start + file_load_va
dq program_headers_start
dq section_headers_start
dd 0
dw 64
dw 0x38
dw 1
dw 0x40
dw 3
dw 2

program_headers_start:
dd 1
dd 5
dq 0
dq file_load_va
dq file_load_va
dq string_table
dq string_table
dq 0x200000

section_headers_start:
times 0x40 db 0

dd text_section_name - string_table
dd 1
dq 6
dq file_load_va
dq 0
dq file_end
dd 0
dd 0
dq 16
dq 0

dd string_table_name - string_table
dd 3
dq 0
dq file_load_va + string_table
dq string_table
dq string_table_end - string_table
dd 0
dd 0
dq 1
dq 0

_start:
    mov rdi, file_load_va + filepath
    xor rsi, rsi
    mov rax, 2
    syscall

    mov rdi, 1
    mov rsi, rax
    mov rdx, 0
    mov r10, 0x100
    mov rax, 0x28
    syscall

    mov rax, 0x3c
    xor rdi, rdi
    syscall

string_table:
db 0
text_section_name:
db ".text", 0
string_table_name:
db ".shstrtab", 0
filepath:
db "flag.txt", 0
string_table_end:
file_end:
