# flipping text loses some information (capitalisation on characters like K, R, B),
# but we can still understand the script enough by flipping it to realise we need
# to add a print statement at the end

_FLIPS = ['?', '¿', '\'', ',', ',', '\'', '[', ']', ']', '[', '!', '¡', 'a', 'ɐ', 'b', 'q', 'c', 'ɔ', 'd', 'p', 'e', 'ǝ', 'f', 'ɟ', 'g', 'ƃ', 'h', 'ɥ', 'i', 'ᴉ', 'j', 'ɾ', 'k', 'ʞ', 'l', 'l', 'm', 'ɯ', 'n', 'u', 'p', 'd', 'q', 'b', 'r', 'ɹ', 's', 's', 't', 'ʇ', 'u', 'n', 'v', 'ʌ', 'w', 'ʍ', 'x', 'x', 'y', 'ʎ', 'z', 'z', 'A', '∀', 'B', 'q', 'C', 'Ɔ', 'D', 'D', 'E', 'Ǝ', 'F', 'Ⅎ', 'G', 'פ', 'I', 'I', 'F', 'ſ', 'K', 'ʞ', 'L', '˥', 'M', 'W', 'N', 'N', 'O', 'O', 'P', 'Ԁ', 'Q', 'Q', 'R', 'ɹ', 'S', 'S', 'T', '┴', 'U', '∩', 'V', 'Λ', 'W', 'M', 'X', 'X', 'Y', '⅄', 'Z', 'Z', '0', '0', '1', 'Ɩ', '2', 'ᄅ', '3', 'Ɛ', '4', 'ㄣ', '5', 'ϛ', '6', '9', '7', 'ㄥ', '8', '8', '9', '6', '(', ')', ')', '(', '<', '>', '>', '<', '"', '„']
FLIPS = { _FLIPS[i]: _FLIPS[i+1] for i in range(0, len(_FLIPS), 2) }
FLIPS |= { _FLIPS[i+1]: _FLIPS[i] for i in range(0, len(_FLIPS), 2) }

upside_down = open('../publish/mate.aussie', 'r').read().splitlines()
flipped = list('\n'.join([s[::-1] for s in upside_down[::-1]]))
for i, c in enumerate(flipped):
    if c in FLIPS:
        flipped[i] = FLIPS[c]

flipped = ''.join(flipped)
print(flipped)
