import asyncio
import socket
import struct

from .log import logger

loop = asyncio.get_event_loop()


class Socks5Server:

    def __init__(self):
        self.connections = {}

    def start_server(self, host, port):
        logger.info('START_SERVER', host=host, port=port)
        return asyncio.start_server(self.accept_client, host=host, port=port)

    def accept_client(self, reader, writer):
        future = asyncio.ensure_future(self.handle_client(reader, writer))
        conn_id = hex(id(future))
        self.connections[conn_id] = (reader, writer)

        host, port, *_ = writer.get_extra_info('peername')
        future.add_done_callback(self.close_client)
        logger.info('OPEN_CONNECTION', host=host, port=port, conn_id=conn_id)

    def close_client(self, future):
        conn_id = hex(id(future))
        _, writer = self.connections.pop(conn_id)
        host, port, *_ = writer.get_extra_info('peername')
        logger.info('CLOSE_CONNECTION', host=host, port=port, conn_id=conn_id)

        # Clean up
        writer.close()

    async def handle_client(self, reader, writer):
        try:
            # Read version, nmethods, methods
            version, nmethods = await reader.readexactly(2)
            logger.debug('RECEIVE_READ', version=version, nmethods=nmethods)
            methods = await reader.readexactly(nmethods)
            logger.debug('RECEIVE_READ', version=version, nmethods=nmethods, methods=methods)

            # Prevent blocking
            #if not data:
            #    return

            # Tell client version 5, no auth
            writer.write(b'\x05\x00')
            await writer.drain()

            # Receive request: version, cmd, rsv (0), atyp, dst addr, dst port
            version, cmd, _, atyp = await reader.readexactly(4)
            logger.debug('RECEIVE_READ', version=version, cmd=cmd, atyp=atyp)
            if cmd != 1:
                # We only handle connect
                return
            if atyp in (1, 4):
                # ip4 or ip6
                read_len = 4 * int(atyp)
            elif atyp == 3:
                read_len = int(await reader.readexactly(1))
            else:
                # bad atyp
                return 
            dest_addr = '.'.join(str(int(x)) for x in await reader.readexactly(read_len))
            dest_port, = struct.unpack(b'!H', (await reader.readexactly(2)))
            logger.debug('RECEIVE_READ', dest_addr=dest_addr, dest_port=dest_port)

            # Send client response: version, rep, rsv (0), atyp, bnd addr, bnd port
            writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
            
            # Let data flow freely between client and remote
            remote_reader, remote_writer = await asyncio.open_connection(host=dest_addr, port=dest_port)
            await self.splice(reader, writer, remote_reader, remote_writer)
        except Exception as e:
            logger.exception('Exception!')
        finally:
            return

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
                    return

                remote_writer.write(data)
                await remote_writer.drain()
                client_read = asyncio.ensure_future(client_reader.read(1024))
                logger.debug('CLIENT_READ', data=data)
            if remote_read in done:
                data = remote_read.result()
                if not data:
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

