from clienthello import create_client_hello_tls13
from serverhello import TLS13ServerHelloParser
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from derive_secrets import get_client_key_and_iv, get_application_key_and_iv, client_finished
from TLS13BodyParser import TLS13BodyParser
from TLS13Wrapper import TLS13Wrapper
import socket

class TLS13Session:
    def __init__(self, addr, port, sock) -> None:
        self.url = addr
        self.port = port
        self.socket = sock
        self.wrapper = None

    def recv(self, length):
        buff = b""
        while length > 0:
            temp = self.socket.recv(length)
            length -= len(temp)
            buff += temp
        return buff

    def handshake(self):
        url = self.url
        private_key = X25519PrivateKey.generate()
        key = private_key.public_key().public_bytes_raw()
        ch = create_client_hello_tls13(url, key)
        self.socket.sendall(ch)
        print("ClientHello sent.")


        parser = TLS13ServerHelloParser(self.socket)
        server_hello_message = parser.parse()
        sh = parser.get_raw()
        length = int(server_hello_message['length'], 16)
        for ext in server_hello_message['extensions']:
            if ext['type'] == '0033':
                data = ext['data']
                key = data[8:]
        server_key = X25519PublicKey.from_public_bytes(bytes.fromhex(key))
        shared_key = private_key.exchange(server_key)

        hello_pre = ch[5:] + sh[5:]
        client_secret, server_secret, client_handshake_key, client_handshake_iv, server_handshake_key, server_handshake_iv = get_client_key_and_iv(shared_key, hello_pre)
    
        parser = TLS13BodyParser(self.socket, server_handshake_key, server_handshake_iv)
        parsed = parser.parse()
        acc = parser.get_acc()
        # print(acc.hex())
        total = hello_pre + acc
        # print(total.hex())
        client_application_key, client_application_iv, server_application_key, server_application_iv = get_application_key_and_iv(shared_key, total)
        self.wrapper = TLS13Wrapper(client_application_key, client_application_iv, server_application_key, server_application_iv)
        cf = client_finished(total, client_secret)
        header = b"\x17\x03\x03\x00\x45"
        # print(cf.hex())
        enc, tag = parser.AES_encrypt(cf, client_handshake_key, client_handshake_iv, header)
        final_cf = header + enc + tag
        self.socket.sendall(final_cf)
        print(self.parse_session_ticket(self.recvnext()))
        print(self.parse_session_ticket(self.recvnext()))   
    def send(self, data):
        if self.wrapper is None:
            self.handshake()
        
        payload = self.wrapper.wrap(data)
        # print(payload)
        self.socket.sendall(payload)

    def recvnext(self):
        if self.wrapper is None:
            self.handshake()
        header = self.recv(5)
        # print(header)
        length = int.from_bytes(header[-2:], 'big')
        payload = self.recv(length)
        # print((header + payload).hex())
        pt = self.wrapper.unwrap(header, payload)
        return pt

    def parse_session_ticket(self, data):
        ticket = {}
        ticket['header'] = data[:4]
        ticket['lifetime'] = data[4:8]
        ticket['age_add'] = data[8:12]
        ticket['nonce_length'] = int(data[12])
        ticket['nonce'] = data[13: 13 + ticket['nonce_length']]
        ticket['ticket_length'] = int.from_bytes(data[13 + ticket['nonce_length']: 13 + ticket['nonce_length'] + 2], 'big')
        ticket['ticket'] = data[13 + ticket['nonce_length'] + 2 : 13 + ticket['nonce_length'] + 2 + ticket['ticket_length']]
        ticket['ext_length'] = int.from_bytes(data[13 + ticket['nonce_length'] + 2 + ticket['ticket_length']: 13 + ticket['nonce_length'] + 2 + ticket['ticket_length'] + 2],'big')
        ticket['extensions'] = data[13 + ticket['nonce_length'] + 2 + ticket['ticket_length'] + 2 : 13 + ticket['nonce_length'] + 2 + ticket['ticket_length'] + 2 + ticket['ext_length']]
        return ticket
if __name__ == "__main__":
    sock = socket.create_connection(("amazon.com", 443))
    conn = TLS13Session("amazon.com", 443, sock)
    # conn.handshake()
    conn.send(b"GET / HTTP/1.1\r\nHost: amazon.com\r\nConnection: close\r\n\r\n")
    print(conn.recvnext().hex())
    # print(conn.recvnext().hex())
    # print(conn.recvnext().hex())