FROM python:3.6-alpine

COPY requirements.txt requirements.txt

RUN python -m venv venv

RUN venv/bin/pip install --no-cache-dir -r requirements.txt

COPY socks5 socks5

COPY boot.sh ./
RUN chmod +x boot.sh

EXPOSE 1488

ENTRYPOINT ["./boot.sh"]
