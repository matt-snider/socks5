# socks5
A socks5 server in Python using asyncio.

# Usage
```
$ python -m socks5.server --help
Usage: server.py [OPTIONS]

  Runs a SOCK5 server.

Options:
  --host TEXT             The interfaces to listen on
  --port INTEGER          The port to listen on
  --allow-no-auth         Whether to allow clients that do not use
                          authentication
  --basic-auth-file PATH  File containing username/password combinations
  --help                  Show this message and exit.
```

# Authentication
The only method currently supported is basic auth, which can be configured
using the --basic-auth-file option. This should point to a file storing
credentials in the format:
```txt
<username>:<password>[:<comment>]
```

# Usage with docker
```
* create you credentials in passwords.txt file
* docker-compose up -d
```

# Usage socks5 for messenger telegram.org
```
create link like: tg://socks?server=ip_or_dns_name&port=port&user=username&pass=passwords.txt
```