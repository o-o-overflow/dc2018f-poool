FROM ubuntu:18.04
RUN apt-get update && apt-get install -y git python-pip libssl1.0.0
COPY requirements.txt /requirements.txt
RUN pip install -r requirements.txt

COPY libcryptonight.so /libcryptonight.so
COPY cryptonight.py /cryptonight.py
COPY stratum.py /stratum.py

COPY exploit1.py /exploit1.py

COPY check1.py /check1.py
