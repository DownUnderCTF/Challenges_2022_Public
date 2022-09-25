import termcolor

def oddbits(n):
	n = ((n & 0x44444444) >> 1) | (n & 0x11111111)
	n = ((n & 0x30303030) >> 2) | (n & 0x03030303)
	n = ((n & 0x0F000F00) >> 4) | (n & 0x000F000F)
	n = ((n & 0x00FF0000) >> 8) | (n & 0x000000FF)
	return n

def tocolor(n):
	# These colors do not match at all the actual tool, but that's OK
	return termcolor.colored(' ',on_color=['on_grey','on_red','on_green','on_yellow','on_blue','on_magenta','on_cyan','on_white'][n])

f = open('../publish/flag.art', 'rb')
packed = f.read()
f.close()

unpacked = b''
for p in packed:
	if p & 0x80:
		run = (p & 0b01111100) >> 2
		off = (p & 0b00000011)
		run += 3
		print(run, off)
		unpacked += unpacked[-run-off:][:run]
	else:
		unpacked += bytes([p])

#print(len(unpacked))
#assert len(unpacked) == 64 ** 2 // 2

canvas = [[0]*64 for _ in range(64)]

cache = set()

for n in range(64 ** 2):
	x = oddbits(n)
	y = oddbits(n >> 1)
	canvas[y][x] = unpacked[n // 2] >> [3, 0][n % 2] & 7

for y in range(64):
	for x in range(64):
		print(end=tocolor(canvas[y][x]))
	print()
