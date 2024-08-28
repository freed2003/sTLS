ck = bytes.fromhex("de2f4c7672723a692319873e5c227606691a32d1c59d8b9f51dbb9352e9ca9cc")
civ = bytes.fromhex("bb007956f474b25de902432f")
sk = bytes.fromhex("01f78623f17e3edcc09e944027ba3218d57c8e0db93cd3ac419309274700ac27")
siv = bytes.fromhex("196a750b0c5049c0cc51a541")

test = TLS13Wrapper(ck, civ, sk, siv)
print(test.wrap(b"ping").hex())