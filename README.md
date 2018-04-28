# socks5

A socks5 server in Python using asyncio.

Works with python >= 3.6

# Installation

This package is available on [pypi](https://pypi.org/project/socks5server/)

Install it with pip:

```sh
$ pip install socks5server
```

Requires: click, kaviar

# Usage

```
$ socks5.server --help
Usage: socks5.server [OPTIONS]

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
