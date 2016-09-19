class BadSocksVersion(Exception):
    pass


class NoAcceptableAuthMethods(Exception):
    pass


class ProtocolException(Exception):
    error_code = b'\x01'


class CommandNotSupported(ProtocolException):
    error_code = b'\x07'


class AddressTypeNotSupported(ProtocolException):
    error_code = b'\x08'

