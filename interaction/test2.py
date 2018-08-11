#!/usr/bin/env python2

from pwn import *
import sys

from stratum import Stratum, CheckFailure, FLAG_PRICE_PER_BIT, FLAG_BITS

TIMEOUT = 30

def main():

    host = sys.argv[1]
    port = int(sys.argv[2])

    conn = remote(host, port)

    s = Stratum(conn)
    s.login()

    # make sure we have a new target
    for _ in xrange(10):
        if s.target == 0:
            time.sleep(0.1)
    assert s.target is not None, 'no target received?'

    # do nonthing and we expect new target every 15s

    cur_target = s.target
    end = time.time() + TIMEOUT
    while time.time() < end:
        time.sleep(16)
        if s.target == cur_target:
            raise CheckFailure('target not updated')
        cur_target = s.target

    sys.exit(0)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print 'ERROR:', e
        sys.exit(1)
    

