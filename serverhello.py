class TLS13ServerHelloParser:
    def __init__(self, socket):
        self.socket = socket
        self.total_buff = b""

    def read_bytes(self, length):
        buff = b""
        while length > 0:
            temp = self.socket.recv(length)
            length -= len(temp)
            buff += temp

        self.total_buff += buff
        return buff

    def parse(self):
        server_hello = {}
        server_hello["type"] = self.read_bytes(1).hex()
        server_hello["legacy_version"] = self.read_bytes(2).hex()
        server_hello["length"] = self.read_bytes(2).hex()
        server_hello["handshake_header"] = self.read_bytes(4).hex()
        server_hello["server_version"] = self.read_bytes(2).hex()
        server_hello["random"] = self.read_bytes(32).hex()
        server_hello["legacy_session_id_echo_length"] = int.from_bytes(
            self.read_bytes(1), "big"
        )
        server_hello["legacy_session_id_echo"] = self.read_bytes(
            server_hello["legacy_session_id_echo_length"]
        ).hex()
        server_hello["cipher_suite"] = self.read_bytes(2).hex()
        server_hello["legacy_compression_method"] = self.read_bytes(1).hex()

        extensions_length = int.from_bytes(self.read_bytes(2), "big")
        server_hello["extensions"] = self.parse_extensions(extensions_length)

        return server_hello

    def get_raw(self):
        return self.total_buff

    def parse_extensions(self, length):
        extensions = []
        pointer = 0
        while pointer < length:
            extension = {}
            extension["type"] = self.read_bytes(2).hex()
            extension_length = int.from_bytes(self.read_bytes(2), "big")
            extension["data"] = self.read_bytes(extension_length).hex()
            extensions.append(extension)
            pointer += 4 + extension_length
        return extensions
