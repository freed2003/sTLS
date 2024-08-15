import socket
import os

def int_to_bytes(value, length):
    return value.to_bytes(length, byteorder='big')

def create_client_hello_tls13(url, key):
    # TLS Record Header
    content_type = b'\x16'  # Handshake
    version = b'\x03\x01'   # Legacy version used in the record layer for TLS 1.3 (0x0301)

    # Handshake Header
    handshake_type = b'\x01'  # ClientHello

    # ClientHello Body
    client_version = b'\x03\x03'  # TLS 1.2 (used in ClientHello for TLS 1.3)
    random_bytes = os.urandom(32)  # 32 bytes of random data

    session_id = os.urandom(32)  # No session ID
    session_id_length = int_to_bytes(len(session_id), 1)

    # TLS 1.3 cipher suites
    cipher_suites = (
        b'\x13\x01'  # TLS_AES_128_GCM_SHA256
        + b'\x13\x02'  # TLS_AES_256_GCM_SHA384
        + b'\x13\x03'  # TLS_CHACHA20_POLY1305_SHA256
    )
    cipher_suites_length = int_to_bytes(len(cipher_suites), 2)

    compression_methods = b'\x01\x00'  # No compression
    compression_methods_length = int_to_bytes(len(compression_methods), 1)

    # Supported Versions Extension
    supported_versions = (
        b'\x00\x2b'  # Extension type (Supported Versions)
        + b'\x00\x03'  # Length of extension data
        + b'\x02'  # Length of versions list
        + b'\x03\x04'  # TLS 1.3 (0x0304)
    )

    # Supported Groups Extension
    supported_groups = (
        b'\x00\x0a'  # Extension type (Supported Groups)
        + b'\x00\x08'  # Length of extension data
        + b'\x00\x06'
        + b'\x00\x1d'  # x25519
        + b'\x00\x17'  # secp256r1
        + b'\x00\x18'  # secp384r1
    )

    # Signature Algorithms Extension
    signature_algorithms = (
        b'\x00\x0d'  # Extension type (Signature Algorithms)
        + b'\x00\x08'  # Length of extension data
        + b'\x00\x06'
        + b'\x04\x03'  # ecdsa_secp256r1_sha256
        + b'\x05\x03'  # rsa_pss_rsae_sha256
        + b'\x08\x04'  # rsa_pss_pss_sha256
    )

    # Key Share Extension
    key_share = (
        b'\x00\x33'  # Extension type (Key Share)
        + b'\x00\x26'  # Length of extension data
        + b'\x00\x24'
        + b'\x00\x1d'  # Key share group (x25519)
        + b'\x00\x20'  # Key share length (32 bytes)
        + key  # Random key share (32 bytes)
    )
    ba = "00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74"
    hex_strings = ba.split()
    hex_numbers = [int(x, 16) for x in hex_strings]
    test = url.encode()
    # Key Share Extension
    server_name = (
        b'\x00\x00'  # Extension type (Key Share)
        + int_to_bytes(len(test) + 5, 2)
        + int_to_bytes(len(test) + 3, 2)
        + b'\x00'
        + int_to_bytes(len(test), 2)
        + test
    )

    session_ticket = (
        b'\x00\x23'
        + b'\x00\x00'
    )

    ec_point_formats = (
        b'\x00\x0b'
        + b'\x00\x04'
        + b'\x03'
        + b'\x00'
        + b'\x01\x02'
    )
    # server_name = bytes(hex_numbers)
    # # Supported Signature Algorithms Certificate Extension
    # signature_algorithms_cert = (
    #     b'\x00\x2b'  # Extension type (Supported Signature Algorithms Cert)
    #     + b'\x00\x08'  # Length of extension data
    #     + b'\x04\x03'  # ecdsa_secp256r1_sha256
    #     + b'\x05\x03'  # rsa_pss_rsae_sha256
    #     + b'\x08\x04'  # rsa_pss_pss_sha256
    # )

    # # Pseudo-Random Function (PRF) Extension
    # prf = (
    #     b'\x00\x2f'  # Extension type (PRF)
    #     + b'\x00\x02'  # Length of extension data
    #     + b'\x01\x00'  # Pseudo-Random Function identifier
    # )

    # # Application Layer Protocol Negotiation (ALPN) Extension
    # alpn = (
    #     b'\x00\x10'  # Extension type (ALPN)
    #     + b'\x00\x0b'  # Length of extension data
    #     + b'\x00\x09'  # Length of ALPN list
    #     + b'\x08http/1.1'  # ALPN protocol (HTTP/1.1)
    # )

    # Assemble all extensions
    extensions = (
        supported_versions
        + server_name
        + supported_groups
        + signature_algorithms
        + key_share
        + session_ticket
        + ec_point_formats
        # + signature_algorithms_cert
        # + prf
        # + alpn
    )
    # print(extensions.hex())
    extensions_length = int_to_bytes(len(extensions), 2)

    # Assemble the ClientHello body
    client_hello_body = (
        client_version
        + random_bytes
        + session_id_length
        + session_id
        + cipher_suites_length
        + cipher_suites
        # + compression_methods_length
        + compression_methods
        + extensions_length
        + extensions
    )

    # Handshake length (without the 4-byte header)
    handshake_length = int_to_bytes(len(client_hello_body), 3)

    # Assemble the Handshake message
    handshake_message = handshake_type + handshake_length + client_hello_body

    # TLS Record Layer length
    record_layer_length = int_to_bytes(len(handshake_message), 2)

    # Assemble the full TLS Record
    tls_record = content_type + version + record_layer_length + handshake_message

    return tls_record

def send_client_hello(host, port):
    client_hello_message = create_client_hello_tls13('amazon.com')

    with socket.create_connection((host, port)) as sock:
        sock.sendall(client_hello_message)
        print(client_hello_message.hex())
        print("ClientHello sent.")

        # Optionally, receive and print the server's response
        response = sock.recv(8092)
        print("Received response:", response.hex())

if __name__ == "__main__":
    send_client_hello("amazon.com", 443)
