from clienthello import create_client_hello_tls13
from serverhello import TLS13ServerHelloParser
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from derive_secrets import get_client_key_and_iv
import socket
def main():
    url = 'amazon.com'
    with socket.create_connection((url, 443)) as sock:
        private_key = X25519PrivateKey.generate()
        key = private_key.private_bytes_raw()
        ch = create_client_hello_tls13(url, key)
        sock.sendall(ch)
        print("ClientHello sent.")

        # Optionally, receive and print the server's response
        response = sock.recv(8092)
        print("Received response")
        parser = TLS13ServerHelloParser(response)
        server_hello_message = parser.parse()
        length = int(server_hello_message['length'], 16)
        for ext in server_hello_message['extensions']:
            if ext['type'] == '0033':
                data = ext['data']
                key = data[8:]
        server_key = X25519PublicKey.from_public_bytes(bytes.fromhex(key))
        shared_key = private_key.exchange(server_key)

        hello_pre = ch[5:] + response[5: 5 + length]
        client_handshake_key, client_handshake_iv, server_handshake_key, server_handshake_iv = get_client_key_and_iv(shared_key, hello_pre)
if __name__ == "__main__":
    main()