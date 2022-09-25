from Crypto.Util.number import long_to_bytes
from hashlib import sha256
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES

ct = bytes.fromhex('85534f055c72f11369903af5a8ac64e2f4cbf27759803041083d0417b5f0aaeac0490f018b117dd4376edd6b1c15ba02')

p = 275344354044844896633734474527970577743
a = [2367876727, 2244612523, 2917227559, 2575298459, 3408491237, 3106829771, 3453352037]
α = [843080574448125383364376261369231843, 1039408776321575817285200998271834893, 712968634774716283037350592580404447, 1166166982652236924913773279075312777, 718531329791776442172712265596025287, 766989326986683912901762053647270531, 985639176179141999067719753673114239]

M = Matrix(GF(p), [a])
M = M.stack(Matrix.identity(len(a) - 1).augment(Matrix.column([0] * (len(a) - 1))))
order = prod([p^len(a) - p^k for k in range(0, len(a))])
n = int(pow(2, 2^1337, order)) - 6
fn = (M^n * vector(α[::-1]))[0]

key = sha256(str(fn).encode()).digest()
aes = AES.new(key, AES.MODE_ECB)
flag = unpad(aes.decrypt(ct), 16)
print(flag.decode())
