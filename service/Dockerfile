FROM ubuntu:18.04
RUN apt-get update && apt-get install -y xinetd libssl1.1
RUN touch /flag && chmod 644 /flag && echo -n "TESTFLAG" | shasum -a 512 | cut -c 1-48  > /flag
COPY service.conf /service.conf

COPY src/schitzo /usr/bin/timeout
COPY src/wrapper.sh /wrapper.sh
COPY src/libcryptonight.so /usr/lib/
COPY src/poool /poool
RUN chmod 755 /poool

EXPOSE 10001
CMD ["/usr/sbin/xinetd", "-dontfork", "-f", "/service.conf"]
