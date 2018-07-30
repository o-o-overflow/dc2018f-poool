FROM python:2.7-alpine

ENV TERM linux

RUN apk update && apk add --no-cache git netcat-openbsd openssl-dev libffi-dev g++ linux-headers make bash
COPY requirements.txt /requirements.txt
RUN pip install -r requirements.txt

COPY libcryptonight.so /libcryptonight.so
COPY cryptonight.py /cryptonight.py
COPY stratum.py /stratum.py

COPY exploit1.py /exploit1.py

COPY check1.py /check1.py