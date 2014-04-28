from ssl_analyze.tls.buffer import Buffer, Reader
from ssl_analyze.tls.handshake import (
    ClientHello,
    ServerHello,
)
from ssl_analyze.tls.packet import RecordHeader3, Alert
from ssl_analyze.tls.parameters import (
    dict_key,
    TLS_CIPHER_SUITE,
    TLS_VERSION,
    AlertDescription,
    CipherSuite,
    ContentType,
    HandshakeType,
    Version,
)
from ssl_analyze.util import get_random_bytes


class Connection(object):
    def __init__(self, remote, tls_version=None):
        self.version = Version.TLSv1_2
        self.remote = remote
        if isinstance(tls_version, basestring):
            self.client_version = getattr(Version, dict_key(tls_version))
        else:
            self.client_version = tls_version or self.version

        self._handshake_buffer = []

    def handshakeClientCert(self, serverName, cipher_suites=[]):
        # Send client Hello
        for result in self._sendClientHello(serverName, cipher_suites):
            if result in (0, 1):
                yield result
            else:
                break
        clientHello = result

        # Receive server Hello
        for result in self._recvServerHello(clientHello):
            if result in (0, 1):
                yield result
            else:
                break
        serverHello = result

    def _recvServerHello(self, clientHello):
        for result in self._recv_message(ContentType.handshake,
                                         HandshakeType.server_hello):
            if result in (0, 1):
                yield result
            else:
                break
        serverHello = result
        self.version = serverHello.server_version
        yield serverHello

    def _sendClientHello(self, serverName, cipher_suites):
        clientHello = ClientHello()
        clientHello.cipher_suites = cipher_suites
        clientHello.random = get_random_bytes(32)
        clientHello.client_version = self.client_version
        clientHello.server_name = bytearray(serverName, 'utf_8')
        for result in self._send_message(clientHello):
            yield result
        yield clientHello

    def _recv_message(self, expected_type, secondary_type=None):
        if not isinstance(expected_type, tuple):
            expected_type= (expected_type,)

        while True:
            for result in self._recv_next_record():
                if result in (0, 1):
                    yield result
            record_header, r = result
            content_type = record_header.content_type

            if content_type == ContentType.application_data:
                if r.pos == len(r):
                    continue

            if content_type not in expected_type:
                if content_type == ContentType.alert:
                    Alert().parse(r).throw()

                raise ValueError('Unexpected record type {}'.format(content_type))

            # Parse based on content_type
            if content_type == ContentType.alert:
                yield Alert().parse(r)

            elif content_type == ContentType.handshake:
                if not isinstance(secondary_type, tuple):
                    secondary_type = (secondary_type,)

                if record_header.v2:
                    sub_type = r.get(1)
                    if sub_type != HandshakeType.client_hello:
                        raise TypeError('Expected client hello')
                    if HandshakeType.client_hello not in secondary_type:
                        raise TypeError('Unexpected message')
                    sub_type = HandshakeType.client_hello

                else:
                    sub_type = r.get(1)
                    if sub_type not in secondary_type:
                        raise TypeError('Unexpected message {}'.format(sub_type))

                if sub_type == HandshakeType.client_hello:
                    yield ClientHello(record_header.v2).parse(r)
                elif sub_type == HandshakeType.server_hello:
                    yield ServerHello(record_header.v2).parse(r)
                else:
                    raise AssertionError(sub_type)

    def _recv_next_record(self):
        if self._handshake_buffer:
            record_header, r = self._handshake_buffer.pop(0)
            yield (record_header, r)
            return

        # Nothing in the buffer, get new data from socket
        b = bytearray(0)
        record_header_size = 1
        v2 = False

        while True:
            s = self.remote.recv(record_header_size - len(b))
            if len(s) == 0:
                raise ValueError('Connection closed while reading record header')

            b += bytearray(s)
            if len(b) == 1:
                if b[0] in ContentType.all:
                    v2 = False
                    record_header_size = 5
                elif b[0] == 128:
                    v2 = True
                    record_header_size = 2
                else:
                    raise SyntaxError('Received record header with invalid type')
            if len(b) == record_header_size:
                break  # We're done here

        if v2:
            raise Exception('No SSLv2 support')
        else:
            r = RecordHeader3().parse(Reader(b))

        if len(r) > 0x4800:
            # Send out overflow error
            raise SyntaxError('Record header length overflow')

        # Read the record from the network
        b = bytearray(0)
        while True:
            s = self.remote.recv(len(r) - len(b))
            if len(s) == 0:
                raise ValueError('Connection closed while reading record')

            b += bytearray(s)
            if len(b) == len(r):
                break  # We're done here

        p = Reader(b)
        # If it doesn't contain handshake messages, we can just return it
        if r.content_type != ContentType.handshake:
            yield (r, p)

        # If it's an SSLv2 ClientHello, we can return it as well
        elif r.v2:
            yield (r, p)

        # Otherwise, we have to loop through and add the handshake messages to
        # the handshake buffer
        else:
            while True:
                if p.pos == len(b):  # At the end of the record header buffer
                    if not self._handshake_buffer:
                        for result in self._send_error(
                                AlertDescription.decode_error,
                                'Received empty handshake record',
                            ):
                            yield result
                    break

                # Needs at least 4 bytes
                if p.pos + 4 > len(b):
                    for result in self._send_error(
                            AlertDescription.decode_error,
                            'A record ahs a partial handshake message'
                        ):
                        yield result

                p.get(1)  # Skip over type
                message_size = p.get(3)
                if p.pos + message_size > len(b):
                    raise ValueError('Not enough data')

                handshake_pair = (r, b[p.pos - 4:p.pos + message_size])
                self._handshake_buffer.append(handshake_pair)
                p.pos += message_size

            # Return the first handshake in the buffer
            record_header, b = self._handshake_buffer.pop(0)
            yield (record_header, Reader(b))

    def _send_message(self, message):
        b = message.render()
        if len(b) == 0:
            return  # Nothing to do

        content_type = message.content_type

        # Add record header
        r = RecordHeader3()
        r.content_type = content_type
        r.version = self.client_version
        r.size = len(b)
        s = r.render() + b

        while True:
            sent = self.remote.send(s)
            if sent == len(s):
                return
            else:
                s = s[sent:]
                yield 1
