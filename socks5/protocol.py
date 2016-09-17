from collections import namedtuple
from enum import Enum


class Socks5Protocol:

    def __init__(self, reader, writer, auth_providers=None):
        self.reader = reader
        self.writer = writer

        # TODO: make auth customizable, support other methods
        self.auth_providers = {}

    async def negotiate_auth(self):
        version, nmethods = await self.reader.readexactly(2)
        if version != 5:
            raise BadSocksVersion(version)
        methods = await self.reader.readexactly(nmethods)
        print(methods)
        if AuthMethod.none.value in methods:
            self.writer.write(b'\x05' + AuthMethod.none.value)
            await self.writer.drain()
        else:
            self.writer.write(b'\x05\xff')
            await self.writer.drain()
            raise NoSupportedAuthMethods(methods)
        return AuthMethod.none


class ProtocolException(Exception):
    pass


class BadSocksVersion(ProtocolException):
    pass


class NoSupportedAuthMethods(ProtocolException):
    pass


class AuthMethod(Enum):
    none = b'\x00'
    gssapi = b'\x01'
    username_password = b'\x02'
    not_acceptable = b'\xff'


Request = namedtuple('Request', ['version', 'command', 'address_type', 
                                 'dest_address', 'dest_port'])

Reply = namedtuple('Reply', ['version', 'reply', 'address_type', 
                             'bind_address', 'bind_port'])

