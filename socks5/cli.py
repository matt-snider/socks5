import asyncio
import click

from .exceptions import ImproperlyConfigured
from .server import Socks5Server


@click.command()
@click.option('--host', default='127.0.0.1',
              help='The interfaces to listen on')
@click.option('--port', default=1080,
              help='The port to listen on')
@click.option('--allow-no-auth', is_flag=True,
              help='Whether to allow clients that do not use authentication')
@click.option('--basic-auth-file', type=click.Path(exists=True),
              help='File containing username/password combinations')
def run_server(host, port, allow_no_auth, basic_auth_file):
    """Runs a SOCK5 server."""
    loop = asyncio.get_event_loop()
    try:
        server = Socks5Server(allow_no_auth=allow_no_auth,
                              basic_auth_user_file=basic_auth_file)
        f = server.start_server(host, port)
        loop.run_until_complete(f)
        loop.run_forever()
    except ImproperlyConfigured as e:
        raise click.UsageError(str(e))
