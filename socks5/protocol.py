import struct

from collections import namedtuple
from enum import Enum

from . import exceptions


class Socks5Protocol:

    def __init__(self, reader, writer, auth_providers=None):
        self.reader = reader
        self.writer = writer

        # TODO: make auth customizable, support other methods
        self.auth_providers = {}
        self.request_received = False

    async def negotiate_auth(self):
        version, nmethods = await self.reader.readexactly(2)
        if version != 5:
            raise exceptions.BadSocksVersion(version)
        methods = await self.reader.readexactly(nmethods)
        if AuthMethod.none in methods:
            self.writer.write(b'\x05' + AuthMethod.none)
            await self.writer.drain()
        else:
            self.writer.write(b'\x05\xff')
            await self.writer.drain()
        return AuthMethod.none

    async def read_request(self):
        version, cmd, _, atyp = await self.reader.readexactly(4)
        cmd, atyp = Command(bytes([cmd])), AddressType(bytes([atyp]))
        if atyp == AddressType.domain_name:
            read_len = int(await self.reader.readexactly(1))
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

