from string import printable

ct = bytes.fromhex('cb57ba706aae5f275d6d8941b7c7706fe261b7c74d3384390b691c3d982941ac4931c6a4394a1a7b7a336bc3662fd0edab3ff8b31b96d112a026f93fff07e61b')

b2_inv = {}
for c in printable:
    i = ord(c)
    b2 = (i ^ ((i >> 5) | (i << 3))) & 0xff
    b2_inv[b2] = i

flag = b'D'
for b in ct[:-1]:
    b1 = flag[-1]
    b1 = (b1 ^ ((b1 << 1) | (b1 & 1))) & 0xff
    b2 = (b - b1) % 256
    flag += bytes([b2_inv[b2]])

print(flag.decode())
