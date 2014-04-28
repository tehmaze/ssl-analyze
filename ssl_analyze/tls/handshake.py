from .buffer import Buffer, Reader
from .parameters import (
    AuthorizationData,
    ContentType,
    ExtensionType,
    HandshakeType,
    NameType,
)


class Handshake(object):
    def __init__(self, handshake_type):
        self.content_type = ContentType.handshake
        self.handshake_type = handshake_type

    def render_header(self, message):
        header = Buffer()
        header.add(self.handshake_type, 1)
        header.add(len(message), 3)
        return header.data + message.data


class ClientHello(Handshake):
    def __init__(self, v2=False):
        super(ClientHello, self).__init__(HandshakeType.client_hello)
        self.v2 = v2
        self.client_version = (0, 0)
        self.random = bytearray(32)
        self.session_id = bytearray(0)
        self.cipher_suites = []
        self.certificate_types = [AuthorizationData.x509_attr_cert]
        self.server_name = bytearray(0)
        self.compression_methods = [0]

    def parse(self, r):
        if self.v2:
            self.client_version = (r.get(1), r.get(1))
            cipher_specs_size = r.get(2)
            session_id_size = r.get(2)
            random_size = r.get(2)
            self.cipher_suites = r.get_fixed_list(3, cipher_specs_size // 3)
            self.session_id = r.get_fixed(session_id_size)
            self.random = r.get_fixed(random_size)
            if self.random < 32:
                zeros = 32 - len(self.random)
                self.random = bytearray(zeros) + self.random
            self.compression_methods = [0]

        else:
            r.size_check_start(3)
            self.client_version = (r.get(1), r.get(1))
            self.random = r.get_fixed(32)
            self.session_id = r.get_variable(1)
            self.cipher_suites = r.get_variable_list(2, 2)
            self.compression_methods = r.get_variable_list(1, 1)

            # Parse extensions, if any
            if not r.at_size_check:
                total_size = r.get(2)
                total = 0
                start = r.pos

                while total != total_size:
                    ext_type = p.get(2)
                    ext_size = p.get(1)

                    if ext_type == ExtensionType.server_name:
                        server_name_data = r.get_fixed(ext_size)
                        r2 = Reader(server_name_data)
                        r2.size_check_start(2)
                        while True:
                            if r2.at_size_check:
                                break  # No luck
                            else:
                                name_type = r2.get(1)
                                host_name = r2.get_variable(2)
                                if name_type == NameType.host_name:
                                    self.server_name = host_name
                                    break

                    elif ext_type == ExtensionType.cert_type:
                        self.certificate_types = p.get_variable_list(1, 1)

                    else:
                        # Just consume the bytes in the buffer
                        r.get_fixed(ext_size)

                if r.pos - start != ext_size:
                    raise SyntaxError('Odd-size fragment for extension data')

                total += 4 + ext_size

            r.size_check_stop()

        return self

    def render(self):
        b = Buffer()
        b.add(self.client_version[0], 1)
        b.add(self.client_version[1], 1)
        b.add_fixed(self.random, 1)
        b.add_variable(self.session_id, 1, 1)
        b.add_variable(self.cipher_suites, 2, 2)
        b.add_variable(self.compression_methods, 1, 1)

        e = Buffer()  # Extensions
        if self.certificate_types and self.certificate_types != [AuthorizationData.x509_attr_cert]:
            e.add(ExtensionType.cert_type, 2)
            e.add(len(self.certificate_types) + 1, 2)
            e.add_variable(self.certificate_types, 1, 1)

        if self.server_name:
            e.add(ExtensionType.server_name, 2)
            e.add(len(self.server_name) + 5, 2)
            e.add(len(self.server_name) + 3, 2)
            e.add(NameType.host_name, 1)
            e.add_variable(self.server_name, 1, 2)

        if len(e):
            b.add(len(e), 2)
            b.data += e.data

        return self.render_header(b)


class ServerHello(Handshake):
    def __init__(self, v2=False):
        super(ServerHello, self).__init__(HandshakeType.server_hello)
        self.v2 = v2
        self.server_version = (0, 0)
        self.random = bytearray(32)
        self.session_id = bytearray(0)
        self.cipher_suite = 0
        self.certificate_type = AuthorizationData.x509_attr_cert
        self.compression_method = 0

    def parse(self, r):
        r.size_check_start(3)
        self.server_version = (r.get(1), r.get(1))
        self.random = r.get_fixed(32)
        self.session_id = r.get_variable(1)
        self.cipher_suite = r.get(2)
        self.compression_method = r.get(1)

        # Parse extensions, if any
        if not r.at_size_check:
            total_size = r.get(2)
            total = 0

            while total != total_size:
                ext_type = r.get(2)
                ext_size = r.get(2)

                if ext_type == ExtensionType.cert_type:
                    if ext_size != 1:
                        raise SyntaxError()
                    else:
                        self.certificate_type = r.get(1)

                else:
                    # Consume data
                    r.get_fixed(ext_size)

                total += 4 + ext_size

        r.size_check_stop()
        return self

    def render(self):
        b = Buffer()
        b.add(self.server_version[0], 1)
        b.add(self.server_version[1], 1)
        b.add_fixed(self.random, 1)
        b.add_variable(self.session_id, 1, 1)
        b.add(self.cipher_suite, 2)
        b.add(self.compression_method, 1)

        e = Buffer()  # Extensions
        if self.certificate_type and self.certificate_type != AuthorizationData.x509_attr_cert:
            e.add(ExtensionType.cert_type, 2)
            e.add(1, 2)
            e.add(self.certificate_type, 1)

        if len(e):
            b.add(len(e), 2)
            b.data += e.data

        return self.render_done(b)
