from hashlib import sha384, sha256
from Crypto.Cipher import AES
import hmac
import hkdf
def hkdf_extract(salt, input_key_material):
    if input_key_material is None:
        input_key_material = b"\x00" * 32
    return hkdf.hkdf_extract(salt, input_key_material, sha256)

def hkdf_expand_label(secret, label, ctx, length):
    label = b"tls13 " + label

    hkdf_label = (
        length.to_bytes(2, "big")
        + len(label).to_bytes(1, "big")
        + label
        + len(ctx).to_bytes(1, "big")
        + ctx
    )

    return hkdf.hkdf_expand(secret, hkdf_label, length, sha256)

def get_client_key_and_iv(shared_secret, hello_pre):
    early_secret = hkdf_extract(b'\x00', None)

    hasher = sha256()
    hasher.update(b'')
    empty_hash = hasher.digest()

    derived_secret = hkdf_expand_label(early_secret, b'derived', empty_hash, 32)

    handshake_secret = hkdf_extract(derived_secret, shared_secret)

    hasher = sha256()
    hasher.update(hello_pre)
    hello_hash = hasher.digest()

    client_secret = hkdf_expand_label(handshake_secret, b"c hs traffic", hello_hash, 32)
    server_secret = hkdf_expand_label(handshake_secret, b"s hs traffic", hello_hash, 32)

    client_handshake_key = hkdf_expand_label(client_secret, b'key', b"", 16)
    server_handshake_key = hkdf_expand_label(server_secret, b'key', b"", 16)

    client_handshake_iv = hkdf_expand_label(client_secret, b'iv', b"", 12)
    server_handshake_iv = hkdf_expand_label(server_secret, b'iv', b"", 12)

    return (client_secret, server_secret, client_handshake_key, client_handshake_iv, server_handshake_key, server_handshake_iv)

def get_application_key_and_iv(shared_secret, handshake_pre):
    early_secret = hkdf_extract(b'\x00', None)

    hasher = sha256()
    hasher.update(b'')
    empty_hash = hasher.digest()

    derived_secret1 = hkdf_expand_label(early_secret, b'derived', empty_hash, 32)

    handshake_secret = hkdf_extract(derived_secret1, shared_secret)

    hasher = sha256()
    hasher.update(handshake_pre)
    handshake_hash = hasher.digest()

    derived_secret = hkdf_expand_label(handshake_secret, b'derived', empty_hash, 32)

    master_secret = hkdf_extract(derived_secret, None)

    client_secret = hkdf_expand_label(master_secret, b"c ap traffic", handshake_hash, 32)
    server_secret = hkdf_expand_label(master_secret, b"s ap traffic", handshake_hash, 32)

    client_application_key = hkdf_expand_label(client_secret, b'key', b"", 16)
    server_application_key = hkdf_expand_label(server_secret, b'key', b"", 16)

    client_application_iv = hkdf_expand_label(client_secret, b'iv', b"", 12)
    server_application_iv = hkdf_expand_label(server_secret, b'iv', b"", 12)

    return (client_application_key, client_application_iv, server_application_key, server_application_iv)

def client_finished(data, secret):
    header = b"\x14\x00\x00\x30"
    finished_key = hkdf_expand_label(secret, b'finished', b'', 48)
    hasher = sha384()
    hasher.update(data)
    finished_hash = hasher.digest()
    verify_data = hmac.new(finished_key, finished_hash, sha384).digest()
    return(header + verify_data + b"\x16")

if __name__ == "__main__":
    with open("pre.txt", "r") as f:
        pre = f.read()
    with open("total.txt", "r") as f:
        final = f.read()
        agg = bytes.fromhex("".join([i for i in final]))
        pre = bytes.fromhex("".join([i for i in pre]))
        shared = bytes.fromhex("df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624")
        client_secret, server_secret, client_handshake_key, client_handshake_iv, server_handshake_key, server_handshake_iv = get_client_key_and_iv(shared, pre)

        def AES_encrypt(text, key, iv, data):
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            cipher.update(data)
            return cipher.encrypt_and_digest(text)
    
        print(client_finished(agg, client_secret).hex())
        m, t = AES_encrypt(client_finished(agg, client_secret), client_handshake_key, client_handshake_iv, b"\x17\x03\x03\x00\x45")
        print(m.hex())
        print(t.hex())