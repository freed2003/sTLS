from aesctr import AES_CTR
key = os.urandom(16)  # AES-256 key
nonce = os.urandom(16)  # 8 bytes nonce, allows for a 64-bit counter
print(key.hex())
print(nonce.hex())
aes = AES_CTR()