from . import exceptions
from .log import logger

async def user_password(reader, writer):
    _, user_length = await reader.readexactly(2)
    username = await reader.readexactly(int(user_length))
    password_length,  = await reader.readexactly(1)
    password = await reader.readexactly(password_length)

    username = username.decode()
    password = password.decode()

    # TODO: credentials need to come form somewhere
    success = False
    if password == 'password':
        success = True
        writer.write(b'\x01\x00')
    else:
        writer.write(b'\x01\x01')
    await writer.drain()
    if not success:
        raise exceptions.AuthFailed("Bad password for '{}'".format(username))
    return username

