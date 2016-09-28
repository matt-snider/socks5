import asyncio
import socket

from . import exceptions
from .log import logger
from .protocol import AuthMethod, Command, Socks5Connection

loop = asyncio.get_event_loop()


class Socks5Server:

    def __init__(self):
        self.connections = {}
        self.auth_methods = [AuthMethod.username_password, AuthMethod.none]

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
            auth_method = await conn.negotiate_auth(self.auth_methods)
            logger.info('AUTH_NEGOTIATED', method=repr(auth_method))

            # Receive request
            request = await conn.read_request()
            logger.info('REQUEST_RECEIVED', request=str(request))

            # We only handle connect requests for now
            if request.command != Command.connect:
                raise CommandNotSupported(request.command)

            # Send client response: version, rep, rsv (0), atyp, bnd addr, bnd port
            await conn.write_success()
            
            # Let data flow freely between client and remote
            remote_reader, remote_writer = await asyncio.open_connection(
                        host=request.dest_address, port=request.dest_port)
            await self.splice(conn.reader, conn.writer, remote_reader, remote_writer)
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

    async def splice(self, client_reader, client_writer, remote_reader, remote_writer):
        client_read = asyncio.ensure_future(client_reader.read(1024))
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
                client_read = asyncio.ensure_future(client_reader.read(1024))
                logger.debug('CLIENT_READ', data=data)
            if remote_read in done:
                data = remote_read.result()
                if not data:
                    client_read.cancel()
                    return

                client_writer.write(data)
                await client_writer.drain()
                remote_read = asyncio.ensure_future(remote_reader.read(1024))
                logger.debug('REMOTE_READ', data=data)
        client_read.cancel()
        remote_read.cancel()


if __name__ == '__main__':
    server = Socks5Server()
    f = server.start_server(host=None, port=1080)
    loop.run_until_complete(f)
    loop.run_forever()

