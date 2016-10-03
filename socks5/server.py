import asyncio
from functools import partial

from . import exceptions, auth
from .log import logger
from .protocol import AuthMethod, Command, Socks5Connection


class Socks5Server:

    def __init__(self, basic_auth_user_file=None, allow_no_auth=False):
        self.basic_auth_credentials = {}
        self.auth_methods = {}
        self.connections = {}

        if allow_no_auth:
            self.auth_methods[AuthMethod.none] = None
        if basic_auth_user_file:
            self.basic_auth_credentials = self.load_basic_auth_file(basic_auth_user_file)
            basic_auth = partial(auth.user_password,
                                  credentials=self.basic_auth_credentials)
            self.auth_methods[AuthMethod.username_password] = basic_auth

        # When configuration is done, we *must* have at least one auth method
        if not self.auth_methods:
            raise exceptions.ImproperlyConfigured('No auth methods configured')

    def start_server(self, host, port):
        logger.info('START_SERVER', host=host, port=port)
        return asyncio.start_server(self.accept_client, host=host, port=port)

    def accept_client(self, reader, writer):
        host, port, *_ = writer.get_extra_info('peername')
        conn = Socks5Connection(reader, writer, host=host, port=port)

        future = asyncio.ensure_future(self.handle_client(conn))
        future.add_done_callback(self.close_client)
        self.connections[conn.id] = conn
        logger.info('OPEN_CONNECTION', **conn.info)

    def close_client(self, future):
        conn = self.connections.pop(future.result())
        conn.writer.close()
        logger.info('CLOSE_CONNECTION', **conn.info)

    async def handle_client(self, conn):
        try:
            # Do auth negotiation
            auth_method = await conn.negotiate_auth_method(self.auth_methods)
            logger.info('AUTH_METHOD_NEGOTIATED', method=repr(auth_method))

            # Do auth subnegotiation
            result = await self.auth_subnegotiation(auth_method, conn.reader,
                                                    conn.writer)
            logger.info('AUTH_COMPLETED', result=result)

            # Receive request
            request = await conn.read_request()
            logger.info('REQUEST_RECEIVED', request=str(request))

            # We only handle connect requests for now
            if request.command != Command.connect:
                raise exceptions.CommandNotSupported(request.command)

            # Send client response: version, rep, rsv (0), atyp, bnd addr, bnd port
            await conn.write_success()
            
            # Let data flow freely between client and remote
            await self.splice(conn, request)
        except exceptions.ProtocolException as e:
            if conn.request_received:
                await conn.write_error(e)
        except exceptions.BadSocksVersion as e:
            logger.warning('UNSUPPORTED_VERSION', version=e.args)
        except exceptions.AuthFailed as e:
            logger.warning('AUTH_FAILED', reason=e.args[0])
        except Exception as e:
            logger.exception('Exception!')
        finally:
            return conn.id

    async def splice(self, client_conn, socks_request):
        remote_reader, remote_writer = (
                await asyncio.open_connection(
                    host=socks_request.dest_address,
                    port=socks_request.dest_port
                )
        )
        client_read = asyncio.ensure_future(client_conn.reader.read(1024))
        remote_read = asyncio.ensure_future(remote_reader.read(1024))
        while True:
            logger.debug('LOOP')
            done, pending = await asyncio.wait([client_read, remote_read], 
                                               return_when=asyncio.FIRST_COMPLETED)
            if client_read in done:
                data = client_read.result()
                if not data:
                    remote_read.cancel()
                    return

                remote_writer.write(data)
                await remote_writer.drain()
                client_read = asyncio.ensure_future(client_conn.reader.read(1024))
                logger.debug('CLIENT_READ', data=data)
            if remote_read in done:
                data = remote_read.result()
                if not data:
                    client_read.cancel()
                    return

                client_conn.writer.write(data)
                await client_conn.writer.drain()
                remote_read = asyncio.ensure_future(remote_reader.read(1024))
                logger.debug('REMOTE_READ', data=data)
        client_read.cancel()
        remote_read.cancel()

    async def auth_subnegotiation(self, auth_method, reader, writer):
        subnegotiation = self.auth_methods[auth_method]
        if subnegotiation:
            return await subnegotiation(reader, writer)

    def load_basic_auth_file(self, path):
        """Loads a dict mapping usernames to passwords from the given file.

        Each line has the format <username>:<password>[:<comment>]
        """
        credentials = {}
        with open(path) as f:
            for line in f.readlines():
                username, password, _ = line.split(':')
                credentials[username] = password
        return credentials


if __name__ == '__main__':
    from .cli import run_server
    run_server()
