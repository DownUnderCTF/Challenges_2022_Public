#!/usr/bin/env python3

from Crypto.Cipher import AES
from PIL import Image
from tempfile import NamedTemporaryFile
from io import BytesIO
import subprocess, os

KEY = b'downunderctf2022'

iv = bytes.fromhex(input('iv (hex): '))
assert len(iv) == 16 and b'DUCTF' in iv, 'Invalid IV'

data = bytes.fromhex(input('file (hex): '))
assert len(data) % 16 == 0, 'Misaligned file length'
assert len(data) < 1337, 'Oversized file length'

data_buf = BytesIO(data)
img = Image.open(data_buf, formats=['jpeg'])
assert img.width == 13 and img.height == 37, 'Invalid image size'
assert img.getpixel((7, 7)) == (7, 7, 7), 'Invalid image contents'

aes = AES.new(KEY, iv=iv, mode=AES.MODE_CBC)
dec = aes.decrypt(data)
assert dec.startswith(b'\x7fELF'), 'Not an ELF'

f = NamedTemporaryFile(delete=False)
f.write(dec)
f.close()

os.chmod(f.name, 0o777)
pipes = subprocess.Popen([f.name], stdout=subprocess.PIPE)
stdout, _ = pipes.communicate()
print(stdout.decode())

os.remove(f.name)
