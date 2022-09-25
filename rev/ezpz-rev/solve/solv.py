from pwn import *

PUZZLE_SOL = '0101000000001000000101010000101000000001000000000101000110100000000100000010101000000100000000100100001010100000001000000010101000101000000000000000101010010101000000000000000001010100010101000000'

# conn = process('./ezpz')
conn = remote('0.0.0.0', 1337)

conn.sendline(PUZZLE_SOL.encode())
print(conn.recvline().decode())