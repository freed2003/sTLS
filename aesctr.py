from Crypto.Cipher import AES
import os

class AES_CTR:
    def __init__(self, key: bytes, nonce: bytes):
        self.key = key
        self.nonce = nonce

    def _generate_keystream_block(self, counter: int) -> bytes:
        # Combine the nonce and counter to form the input block
        counter_block = self.nonce + counter.to_bytes(16 - len(self.nonce), byteorder='big')
        
        return self.AES_128(self.key, counter_block)

    def _ctr_mode(self, data: bytes) -> bytes:
        output = bytearray()
        for i in range(0, len(data), 16):
            keystream_block = self._generate_keystream_block((i // 16) + 2)
            block = data[i:i + 16]
            output.extend(a ^ b for a, b in zip(block, keystream_block))
        return bytes(output)

    def encrypt(self, plaintext: bytes) -> bytes:
        return self._ctr_mode(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self._ctr_mode(ciphertext)
    
    def AES_128(self, pt):
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(pt)

# Example usage:
key = os.urandom(16)  # AES-256 key
nonce = os.urandom(12)  # 8 bytes nonce, allows for a 64-bit counter
key = bytes.fromhex("9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f")
iv = bytes.fromhex("9563bc8b590f671f488d2da3")
aes_ctr = AES_CTR(key, nonce)

ciphertext = bytes.fromhex("c32c24bd6ab88c6f422c0d")
decrypted_text = aes_ctr.decrypt(ciphertext)

print(f"Ciphertext: {ciphertext.hex()}")
print(f"Decrypted: {decrypted_text.hex()}")
