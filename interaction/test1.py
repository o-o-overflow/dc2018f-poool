#!/usr/bin/env python2

from pwn import *
import sys, os

from stratum import Stratum, CheckFailure, FLAG_PRICE_PER_BIT, FLAG_BITS, DEFAULT_DIFF
from money import superhash

def main():
    host = sys.argv[1]
    port = int(sys.argv[2])

    conn = remote(host, port)

    class TestStratum(Stratum):
        def test_balance(self):
            share = self.get_share()
            balance = self.get_balance()
            # if there is a race between get_share & get_balance, we may see a
            # greater value than expected
            assert share + balance >= self.expected_share, 'expected %s, current share = %s, balance = %s' % (self.expected_share, share, balance)

        def test_set_target(self):
            good_diff = random.randint(100, 400)
            target = '%08x' % (0xffffffff / good_diff) + '0' * 0x38
            self.set_target([target])
            # after the synchronized call, we should have new
            # difficulty/job immediately
            target_ = int(target, 16)
            for _ in xrange(4):
                if self.target != target_:
                    time.sleep(0.1)
            assert self.target == target_, 'target = %s not %s' % (self.target, target_)
            return target_

        def test_submit(self, n=1000, timeout=60):
            self.test_set_target()
            end = time.time() + timeout
            while n > 0:
                if self.try_solve():
                    n -= 1
                if time.time() > end:
                    break

        def test_submit_super(self):
            cur_job = self.job
            hdr = cur_job['header'] + struct.pack('<II', self.nonce1 + cur_job['id'],
                    cur_job['time']).encode('hex')
            solutions = superhash(hdr, DEFAULT_DIFF, 96, 10)
            log.info('got %d solutions', len(solutions))
            for sol in solutions:
                log.debug('sol: %s', sol)
                nonce2, hash_, diff = sol.split()
                res = self.submit(nonce2, cur_job['time'], cur_job['id'])
                # it must be accepted unless we have 15 more solutions (rare & race)
                if res.get('result') != [True]:
                    log.warn('submission rejected? %r', res)
                    cur_diff = (1 << 64) / self.target
                    if diff > cur_diff:
                        raise CheckFailure('%s should not be rejected with diff %s targeting %s' % (hash_, diff, cur_diff))
                    else:
                        break


        def test_random(self):
            selector = random.choice(['balance', 'set_target',
                'submit_super'])
            method = getattr(self, 'test_' + selector)
            method()

    s = TestStratum(conn)
    s.login()

    s.test_submit_super()

    s.test_balance()

    while s.get_share() != 0:
        time.sleep(1)

    balance = s.get_balance()
    log.info('final balance = %s', balance)

    sys.exit(0)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print 'ERROR:', str(e)
        sys.exit(1)
    

