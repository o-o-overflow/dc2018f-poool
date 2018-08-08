FROM ubuntu:18.04
RUN apt-get update && apt-get install -y xinetd libssl1.1
RUN touch /flag && chmod 644 /flag && echo -ne "TESTFLAG" | md5sum | cut -f1 -d' ' > /flag
COPY service.conf /service.conf

COPY src/libcryptonight.so /usr/lib/
COPY src/poool /poool
RUN chmod 755 /poool

EXPOSE 10001
CMD ["/usr/sbin/xinetd", "-filelog", "-", "-dontfork", "-f", "/service.conf"]
