from . import exceptions


async def user_password(reader, writer, credentials):
    _, user_length = await reader.readexactly(2)
    username = await reader.readexactly(int(user_length))
    password_length,  = await reader.readexactly(1)
    password = await reader.readexactly(password_length)

    username = username.decode()
    password = password.decode()

    try:
        success = (password == credentials[username])
    except KeyError:
        success = False

    writer.write(b'\x01' + bytes([not success]))
    await writer.drain()
    if not success:
        raise exceptions.AuthFailed("Bad password for '{}'".format(username))
    return username

