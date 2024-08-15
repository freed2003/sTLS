from hashlib import sha384, sha256
import hmac
import hkdf
def hkdf_extract(salt, input_key_material):
    if input_key_material is None:
        input_key_material = b"\x00" * 32
    return hkdf.hkdf_extract(salt, input_key_material, sha384)

def hkdf_expand_label(secret, label, ctx, length):
    label = b"tls13 " + label

    hkdf_label = (
        length.to_bytes(2, "big")
        + len(label).to_bytes(1, "big")
        + label
        + len(ctx).to_bytes(1, "big")
        + ctx
    )

    return hkdf.hkdf_expand(secret, hkdf_label, length, sha384)

def get_client_key_and_iv(shared_secret, hello_pre):
    early_secret = hkdf_extract(b'\x00', b'\x00' * 48)

    hasher = sha384()
    hasher.update(b'')
    empty_hash = hasher.digest()

    derived_secret = hkdf_expand_label(early_secret, b'derived', empty_hash, 48)

    handshake_secret = hkdf_extract(derived_secret, shared_secret)

    hasher = sha384()
    hasher.update(hello_pre)
    hello_hash = hasher.digest()

    client_secret = hkdf_expand_label(handshake_secret, b"c hs traffic", hello_hash, 48)
    server_secret = hkdf_expand_label(handshake_secret, b"s hs traffic", hello_hash, 48)

    client_handshake_key = hkdf_expand_label(client_secret, b'key', b"", 32)
    server_handshake_key = hkdf_expand_label(server_secret, b'key', b"", 32)

    client_handshake_iv = hkdf_expand_label(client_secret, b'iv', b"", 12)
    server_handshake_iv = hkdf_expand_label(server_secret, b'iv', b"", 12)

    return (client_handshake_key, client_handshake_iv, server_handshake_key, server_handshake_iv)
