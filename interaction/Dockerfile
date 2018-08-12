FROM ubuntu:18.04
RUN apt-get update && apt-get install -y git python-pip libssl1.0.0
COPY requirements.txt /requirements.txt
RUN pip install -r requirements.txt

COPY libcryptonight.so /libcryptonight.so
COPY cryptonight.py /cryptonight.py
COPY stratum.py /stratum.py

COPY exploit1.py /exploit1.py
COPY exploit2.py /exploit2.py
COPY exploit3.py /exploit3.py

COPY test1.py /test1.py
COPY test2.py /test2.py
COPY test3.py /test3.py
COPY sla1.py /sla1.py
COPY poc1.py /poc1.py
COPY test.sh /test.sh
COPY money.py /money.py

ENV TERM linux
