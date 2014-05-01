import socket

from ssl_analyze.log import log
from ssl_analyze.tls.buffer import Buffer, Reader
from ssl_analyze.tls.handshake import (
    Handshake,
    CertificateRequest,
    ClientHello,
    ServerHello,
    ServerHelloDone,
    Certificate,
    ServerKeyExchange,
)
from ssl_analyze.tls.packet import RecordHeader3, Alert
from ssl_analyze.tls.parameters import (
    dict_key,
    TLS_CIPHER_SUITE,
    TLS_CONTENT_TYPE,
    TLS_HANDSHAKE_TYPE,
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
        self._certificates = []

    def close(self):
        self.remote.shutdown(socket.SHUT_RDWR)
        self.remote.close()
        self.remote = None
        self.reset()

    def reset(self):
        self._handshake_buffer = []
        self._certificates = []

    def handshake(self, **kwargs):
        # Send client Hello
        for result in self._send_client_hello(**kwargs):
            if result in (0, 1):
                yield result
            else:
                break
        self.client_hello = result

        # Receive server Hello
        for result in self._recv_server_hello(self.client_hello):
            if result in (0, 1):
                yield result
            else:
                break
        self.server_hello = result

        # Receive server RSA Key Exchange
        for result in self._recv_server_rsa_key_exchange(
                self.client_hello,
                self.server_hello,
            ):
            if result in (0, 1):
                yield result
            else:
                break
        self.server_key_exchange = result

    def resume(self, **kwargs):
        # Send client Hello
        for result in self._send_client_hello(**kwargs):
            if result in (0, 1):
                yield result
            else:
                break
        self.client_hello = result

        # Receive server Hello
        for result in self._recv_server_hello(self.client_hello):
            if result in (0, 1):
                yield result
            else:
                break
        self.server_hello = result

    def get_certificate_chain(self):
        return self._certificates

    def _recv_server_hello(self, clientHello):
        for result in self._recv_message(
                ContentType.handshake,
                HandshakeType.server_hello
            ):
            if result in (0, 1):
                yield result
            else:
                break
        serverHello = result
        self.version = serverHello.server_version
        yield serverHello

    def _recv_server_rsa_key_exchange(self, clientHello, serverHello):
        # Get Certificate[, CertificateRequest], ServerHelloDone
        for result in self._recv_message(
                ContentType.handshake,
                HandshakeType.certificate,
                serverHello.certificate_type
            ):
            if result in (0, 1):
                yield result
            else:
                print result
                break
        serverCertificate = result
        self._certificates = serverCertificate.certificate_chain

        # Get CertificateRequest[, ServerKeyExchange] or ServerHelloDone
        for result in self._recv_message(
                ContentType.handshake,
                (
                    HandshakeType.server_hello_done,
                    HandshakeType.certificate_request,
                    HandshakeType.server_key_exchange,
                ),
            ):
            if result in (0, 1):
                yield result
            else:
                break
        message = result
        certificateRequest = None
        if isinstance(message, CertificateRequest):
            certificateRequest = message
            # We got CertificateRequest, so this must be ServerHelloDone
            for result in self._recv_message(
                    ContentType.handshake,
                    HandshakeType.server_hello_done
                ):
                if result in (0, 1):
                    yield result
                else:
                    break

            serverHelloDone = result

        elif isinstance(message, ServerHelloDone):
            serverHelloDone = message

    def _send_client_hello(self, **kwargs):
        clientHello = ClientHello()
        clientHello.random = get_random_bytes(32)
        clientHello.client_version = self.client_version
        for attr, value in kwargs.iteritems():
            if isinstance(getattr(clientHello, attr), bytearray):
                if not isinstance(value, bytearray):
                    setattr(clientHello, attr, bytearray(value, 'utf_8'))
                else:
                    setattr(clientHello, attr, value)
            else:
                setattr(clientHello, attr, value)
        for result in self._send_message(clientHello):
            yield result
        yield clientHello

    def _recv_message(self, expected_type, secondary_type=None,
                      constructorType=None):

        if not isinstance(expected_type, tuple):
            expected_type= (expected_type,)

        while True:
            for result in self._recv_next_record():
                if result in (0, 1):
                    yield result
            record_header, r = result
            content_type = record_header.content_type

            log.debug('Received {} record'.format(
                TLS_CONTENT_TYPE.get(content_type, content_type)
            ))
            if content_type == ContentType.application_data:
                if r.pos == len(r):
                    continue

            if content_type not in expected_type:
                if content_type == ContentType.alert:
                    Alert().parse(r).throw()

                raise ValueError('Unexpected record type {}, exptected {}'.format(
                    TLS_CONTENT_TYPE.get(content_type, content_type),
                    map(TLS_CONTENT_TYPE.get, expected_type)
                ))

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
                        raise TypeError(
                            'Unexpected message {} ({}), expected {}/{}'.format(
                            sub_type,
                            TLS_HANDSHAKE_TYPE.get(sub_type, 'unknown'),
                            map(TLS_HANDSHAKE_TYPE.get, expected_type),
                            map(TLS_HANDSHAKE_TYPE.get, secondary_type)
                        ))

                log.debug('... with sub type {}'.format(
                    TLS_HANDSHAKE_TYPE.get(sub_type, sub_type)
                ))

                if sub_type == HandshakeType.client_hello:
                    yield ClientHello(record_header.v2).parse(r)

                elif sub_type == HandshakeType.server_hello:
                    yield ServerHello(record_header.v2).parse(r)

                elif sub_type == HandshakeType.certificate:
                    yield Certificate(constructorType).parse(r)

                elif sub_type == HandshakeType.server_key_exchange:
                    yield ServerKeyExchange(constructorType).parse(r)

                elif sub_type == HandshakeType.server_hello_done:
                    yield ServerHelloDone().parse(r)

                else:
                    raise AssertionError(TLS_HANDSHAKE_TYPE.get(sub_type, sub_type))

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
        log.debug('Sending {} record'.format(
            TLS_CONTENT_TYPE.get(content_type, content_type)
        ))
        if isinstance(message, Handshake):
            log.debug('... with sub type {}'.format(
                TLS_HANDSHAKE_TYPE.get(message.handshake_type,
                                       message.handshake_type)
            ))

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
