#!/bin/sh
source venv/bin/activate
exec python -m socks5.server --host 0.0.0.0 --port 1488 --basic-auth-file passwords.txt