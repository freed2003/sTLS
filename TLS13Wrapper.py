from Crypto.Cipher import AES


class TLS13Wrapper:

    def __init__(self, ck, ci, sk, si) -> None:
        self.client_key = ck
        self.client_iv = ci
        self.server_key = sk
        self.server_iv = si
        self.c_count = 0
        self.s_count = 0

    def wrap(self, data):
        header = b"\x17\x03\x03"
        length = (len(data) + 17).to_bytes(2, "big")
        iv = self.xor_iv(self.client_iv, self.c_count)
        self.c_count += 1
        enc, tag = self.AES_encrypt(
            data + b"\x17", self.client_key, iv, header + length
        )
        return header + length + enc + tag

    def unwrap(self, header, data):
        iv = self.xor_iv(self.server_iv, self.s_count)
        self.s_count += 1
        dec = self.AES_decrypt(data[:-16], self.server_key, iv, header, data[-16:])
        return dec

    def AES_decrypt(self, text, key, iv, data, tag):
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        cipher.update(data)
        return cipher.decrypt_and_verify(text, tag)

    def AES_encrypt(self, text, key, iv, data):
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        cipher.update(data)
        return cipher.encrypt_and_digest(text)

    def xor_iv(self, a, b):
        if type(a) == bytes:
            a = int.from_bytes(a, "big")
        if type(b) == bytes:
            b = int.from_bytes(b, "big")

        return (a ^ b).to_bytes(12, "big")
