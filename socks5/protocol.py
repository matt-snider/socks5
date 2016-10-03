import struct
import uuid

from collections import namedtuple
from enum import Enum

from . import exceptions


class Socks5Connection:

    def __init__(self, reader, writer, **info):
        self.id = str(uuid.uuid4())
        self.reader = reader
        self.writer = writer
        self.info = info
        self.info['id'] = self.id

    async def negotiate_auth_method(self, supported_methods):
        version, nmethods = await self.reader.readexactly(2)
        if version != 5:
            raise exceptions.BadSocksVersion(version)
        client_methods = set(AuthMethod(bytes([x])) for x in
                             await self.reader.readexactly(nmethods))

        # Use the best matching auth method using the order
        # of `supported_methods` as a preference
        common_methods = [x for x in supported_methods if x in client_methods]
        selected = common_methods[0] if common_methods else AuthMethod.not_acceptable
        self.writer.write(b'\x05' + selected)
        await self.writer.drain()
        if selected == AuthMethod.not_acceptable:
            raise exceptions.AuthFailed('No acceptable methods: {}'
                                        .format(client_methods))
        return selected

    async def read_request(self):
        version, cmd, _, atyp = await self.reader.readexactly(4)
        cmd, atyp = Command(bytes([cmd])), AddressType(bytes([atyp]))
        if atyp == AddressType.domain_name:
            read_len, = await self.reader.readexactly(1)
        elif atyp in AddressType.ipv4 + AddressType.ipv6:
            read_len = 4 * struct.unpack('B', atyp)[0]
        else:
            raise exceptions.AddressTypeNotSupported(atyp)
        dest_addr = '.'.join(str(int(x)) for x in await self.reader.readexactly(read_len))
        dest_port, = struct.unpack(b'!H', (await self.reader.readexactly(2)))
        self.request_received = True
        return Request(version=version, command=cmd, address_type=atyp,
                       dest_address=dest_addr, dest_port=dest_port)

    async def _write_reply(self, reply_code):
        self.writer.write(struct.pack('!BBxBxxxxxx', 5, reply_code, 0x01))
        await self.writer.drain()

    async def write_error(self, error):
        await self._write_reply(error.error_code)

    async def write_success(self):
        await self._write_reply(0)


class AuthMethod(bytes, Enum):
    none = b'\x00'
    gssapi = b'\x01'
    username_password = b'\x02'
    not_acceptable = b'\xff'


class Command(bytes, Enum):
    connect = b'\x01'
    bind = b'\x02'
    udp_associate = b'\x03'


class AddressType(bytes, Enum):
    domain_name = b'\x03'
    ipv4 = b'\x01'
    ipv6 = b'\x04'


Request = namedtuple('Request', ['version', 'command', 'address_type', 
                                 'dest_address', 'dest_port'])

