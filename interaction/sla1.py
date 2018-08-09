#!/usr/bin/env python2

from pwn import *
import sys

from stratum import Stratum, CheckFailure, FLAG_PRICE_PER_BIT, FLAG_BITS, REAL_FLAG

TIMEOUT = 60

def main():

    host = sys.argv[1]
    port = int(sys.argv[2])

    conn = remote(host, port)

    s = Stratum(conn)
    s.login()

    end = time.time() + TIMEOUT
    while time.time() < end:
        for _  in xrange(1000): # expected in 20s
            s.try_solve()

    share = s.get_share()
    balance = s.get_balance()
    speed = s.get_speed()
    log.info('share = %d balance = %s speed = %s expected total = %d', share, balance,
            speed, s.expected_share)
    if share + balance < s.expected_share:
        # if there is a race between get_share & get_balance, we may see a
        # greater value than expected
        raise CheckFailure('share incorrect')

    # wait until the share goes to balance
    while s.get_share() > 0:
        time.sleep(2)

    balance = s.get_balance()
    log.info('final balance = %s', balance)

    nbits = balance / FLAG_PRICE_PER_BIT
    if nbits > 0:
        log.info('try get %d bits of flag', nbits)
        indices = range(FLAG_BITS)
        random.shuffle(indices)
        indices = indices[:nbits]
        res = s.query_flag(indices)
        for i, idx in enumerate(indices):
            # TODO check with flag oracle
            log.info('bit #%d = %s, expeceted %s', idx, res[i], REAL_FLAG[idx])
            if REAL_FLAG[idx] != res[i]:
                raise CheckFailure('incorrect bit')

    sys.exit(0)


if __name__ == '__main__':
    main()
    

