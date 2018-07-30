#!/usr/bin/env python2

from pwn import *
import sys

from stratum import Stratum
from cryptonight import ooohash, job_hash

def main():

    host = sys.argv[1]
    port = int(sys.argv[2])

    conn = remote(host, port)

    s = Stratum(conn)
    s.login()

    hdr = s.job['header'].decode('hex') + struct.pack('<I', s.nonce1)
    i = 0
    v = 'f' * 40
    while True:
        h = job_hash(hdr, i, s.job['time'])
        if h < v:
            v = h
            d = int(v, 16)
            print i, v, (1 << 256) // d
            if d < s.target:
                break
        i += 1
    print s.submit(struct.pack('>I', i).encode('hex'), s.job['time'])
    print s.get_share()

    sys.exit(0)


if __name__ == '__main__':
    main()
    

