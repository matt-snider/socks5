import asyncio
import logging
import socket
import struct


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('socks5')

clients = {}

def accept_client(client_reader, client_writer):
    future = asyncio.ensure_future(handle_client(client_reader, client_writer))
    client_id, host = hex(id(future)), client_writer.get_extra_info('peername')
    clients[client_id] = (client_reader, client_writer)

    def client_done(task):
        del clients[client_id]
        client_writer.close()
        logger.info('CONNECTION_CLOSED: id={} host={}'.format(client_id, host))

    logger.info('NEW_CONNECTION: id={} host={}'.format(client_id, host))
    future.add_done_callback(client_done)


async def handle_client(client_reader, client_writer):
    try:
        # Read version, nmethods, methods
        version, nmethods = await client_reader.readexactly(2)
        logger.info('READ1 RECEIVED: version={}, nmethods={}'.format(version, nmethods)) 
        methods = await client_reader.readexactly(nmethods)
        logger.info('READ2 RECEIVED: version={}, methods={}'.format(version, methods))

        # Prevent blocking
        #if not data:
        #    return

        # Tell client version 5, no auth
        client_writer.write(b'\x05\x00')
        await client_writer.drain()

        # Receive request: version, cmd, rsv (0), atyp, dst addr, dst port
        version, cmd, _, atyp = await client_reader.readexactly(4)
        logger.info('READ3 RECEIVED: version={}, cmd={}, atyp={}'.format(version, cmd, atyp))
        if cmd != 1:
            # We only handle connect
            return
        if atyp in (1, 4):
            # ip4 or ip6
            read_len = 4 * int(atyp)
        elif atyp == 3:
            read_len = int(await client_reader.readexactly(1))
        else:
            # bad atyp
            return 
        dest_addr = '.'.join(str(int(x)) for x in await client_reader.readexactly(read_len))
        dest_port, = struct.unpack(b'!H', (await client_reader.readexactly(2)))
        logger.info('READ4 RECEIVED: dest_addr={}, dest_port={}'.format(dest_addr, dest_port))

        # Send client response: version, rep, rsv (0), atyp, bnd addr, bnd port
        client_writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        await client_writer.drain()

        # Do connection and transfer data
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((dest_addr, dest_port))
            reader, writer = await asyncio.open_connection(sock=s)

            client_read = asyncio.ensure_future(client_reader.read(1024))
            remote_read = asyncio.ensure_future(reader.read(1024))
            while True:
                done, pending = await asyncio.wait([client_read, remote_read], 
                                                   return_when=asyncio.FIRST_COMPLETED)
                if client_read in done:
                    data = client_read.result()
                    if not data:
                        return

                    writer.write(data)
                    await writer.drain()
                    client_read = asyncio.ensure_future(client_reader.read(1024))
                if remote_read in done:
                    data = remote_read.result()
                    if not data:
                        return

                    client_writer.write(remote_read.result())
                    await client_writer.drain()
                    remote_read = asyncio.ensure_future(reader.read(1024))
    except Exception as e:
        logger.exception('Exception!')
    finally:
        return


if __name__ == '__main__':
    logger.info('STARTING_SERVER')
    loop = asyncio.get_event_loop()
    f = asyncio.start_server(accept_client, host=None, port=1080)
    loop.run_until_complete(f)
    loop.run_forever()

