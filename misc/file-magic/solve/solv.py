from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from PIL import Image
from io import BytesIO

key = b'downunderctf2022'

# generate the jpg
img = Image.new('RGB', (13, 37))

# trial and error to get (7, 7) to (7, 7, 7) after compression
img.putpixel((6, 7), (69, 69, 69))
img_buf = BytesIO()
img.save(img_buf, format='jpeg')
jpg_data = img_buf.getvalue()

# calculate the IV as in https://raw.githubusercontent.com/angea/pocorgtfo/master/contents/articles/03-11.pdf
catflag_elf = open('./catflag', 'rb').read()
l = len(catflag_elf) + 9 + ((len(catflag_elf) % 16) or 16)
aes = AES.new(key, mode=AES.MODE_ECB)
c0 = aes.decrypt(b'\xff\xd8\xff\xff\xfe' + l.to_bytes(2, 'big') + b'xxxxxxxxx')

# we can set the 8-12th bytes of ELF header without issues
catflag_elf = catflag_elf[:8] + strxor(c0[8:13], b'DUCTF') + catflag_elf[13:]
iv = strxor(c0, catflag_elf[:16])

aes = AES.new(key, iv=iv, mode=AES.MODE_CBC)
cat_elf_enc = aes.encrypt(pad(catflag_elf, 16)) + jpg_data[2:]

assert b'DUCTF' in iv

# conn = process('./server.py')
conn = remote('0.0.0.0', 1337)
conn.sendlineafter(b'iv (hex): ', iv.hex().encode())
conn.sendlineafter(b'file (hex): ', pad(cat_elf_enc, 16).hex().encode())
print(conn.recvline().decode())
