#!/usr/bin/env python2

from pwn import *
import sys, subprocess

from stratum import Stratum, CheckFailure, FLAG_PRICE_PER_BIT, FLAG_BITS, REAL_FLAG_BITS
from money import superhash

TIMEOUT = 200

def main():

    host = sys.argv[1]
    port = int(sys.argv[2])

    # context.log_level = 'DEBUG'

    conn = remote(host, port)

    s = Stratum(conn)
    s.login()

    good_diff = 50 * 96
    good_target = ['%08x' % (0xFFFFFFFF / good_diff + 1) + '0' * 0x38]

    end = time.time() + TIMEOUT
    while time.time() < end:
        s.set_target(good_target)
        time.sleep(0.5)
        cur_job = s.job
        hdr = cur_job['header'] + struct.pack('<II', s.nonce1 + cur_job['id'],
                cur_job['time']).encode('hex')
        solutions = superhash(hdr, good_diff, 96, 13)
        log.info('got %d solutions', len(solutions))
        for sol in solutions:
            log.debug('sol: %s', sol)
            nonce2, hash_, diff = sol.split()
            res = s.submit(nonce2, cur_job['time'], cur_job['id'])
            # it must be accepted unless we have 15 more solutions (rare & race)
            if res.get('result') != [True]:
                log.warn('submission rejected? %r', res)
                if diff > s.target:
                    raise CheckFailure('%s should not be rejected with diff %d targeting %s' % (hash_, diff, s.target))

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
    if nbits > 2:
        log.info('try get %d bits of flag', nbits)
        indices = range(FLAG_BITS)
        random.shuffle(indices)
        indices = indices[:nbits]
        res = s.query_flag(indices)
        assert len(indices) == nbits, 'not enough result'
        for i, idx in enumerate(indices):
            log.info('bit #%d = %s, expeceted %s', idx, res[i],
                    REAL_FLAG_BITS[idx])
            if REAL_FLAG_BITS[idx] != res[i]:
                raise CheckFailure('incorrect bit')
    elif nbits > 0:
        log.warn("we don't work as well as expected")
        raise CheckFailure('?')
    else:
        log.warn('impossible, we can not fetch any bit')
        raise CheckFailure('client cheating?!')

    sys.exit(0)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print 'ERROR:', str(e)
        sys.exit(1)
    

