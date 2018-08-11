from pwn import *
from cryptonight import job_hash
import json, string, threading

FINAL_DIFF = 0x800000
DEFAULT_DIFF = 0x200
FLAG_BITS = 0xc0
FLAG_PRICE_PER_BIT = FINAL_DIFF / FLAG_BITS
REAL_FLAG = hashlib.sha512('TESTFLAG').hexdigest()[:48]
REAL_FLAG_BITS = ''.join(map(lambda _: bin(ord(_))[2:].rjust(8, '0')[::-1], REAL_FLAG.decode('hex')))

class CheckFailure(Exception):
    pass

def gen_username():
    charset = list(set(string.letters + string.digits).difference('IOl0'))
    return 'oO0' + ''.join([random.choice(charset) for _ in xrange(32)])

def difficulty_update(stratum, o):
    params = o.get('params')
    try:
        if params:
            stratum.target = int(params[0], 16)
            log.info('got new target %#x', stratum.target)
            return
    except KeyError as e:
        log.warning('difficulty_update: %r', e)
    raise CheckFailure('no valid target: %r' % o)

def new_job(stratum, o):
    params = o.get('params')
    try:
        if params:
            stratum.job = {
                    'id': int(params[0], 16),
                    'header': params[1],
                    'time': int(params[2], 16)
                    }
            log.info('got new job %r', stratum.job)
            return
    except KeyError as e:
        log.warning('new_job: %r', e)
    raise CheckFailure('no valid job: %r' % o)

class Stratum(object):
    def __init__(self, tube):
        self.tube = tube
        self.id = 0
        self.username = gen_username()

        self.notifications = []
        self.handlers = {
                'mining.set_difficulty': difficulty_update,
                'mining.notify': new_job,
                }

        self.nonce1 = None
        self.nonce2 = 0
        self.target = 0
        self.job = None
        self.expected_share = 0

        self.slots = {}
        self.listener = threading.Thread(target=self.loop, args=())
        self.listener.setDaemon(True)
        self.listener.start()

    def _process_one(self):
        d = self.tube.readline()
        try:
            return json.loads(d)
        except ValueError as e:
            log.warning('invalid json: %s (%r)', d, e)
            return {
                    'method': 'invalid_json', # handlers hack
                    'raw': d
                    }
        return o

    def process_one(self):
        o = self._process_one()
        method = o.get('method')
        if method in self.handlers:
            self.handlers[method](self, o)
        return o

    def request_sync(self, method, params=[], timeout=3):
        self.id += 1
        id_ = self.id
        self.slots[id_] = None
        self.tube.sendline(json.dumps({
            'id': id_,
            'method': method,
            'params': params
            }))
        end = time.time() + timeout
        while self.slots[id_] is None and time.time() < end:
            time.sleep(0.1)
        return self.slots[id_]

    def login(self):
        self.nonce1 = int(self.request_sync('mining.subscribe', [])['result'][1], 16)
        self.request_sync('mining.authorize', [self.username, 'x'])
        log.info('nonce1 = %08x', self.nonce1)

    def submit(self, nonce2, time=None, job_id=None):
        if time is None:
            time = self.job['time']
        if job_id is None:
            job_id = self.job['id']
        return self.request_sync('mining.submit', [self.username, job_id,
            nonce2, '%08x' % time])

    def set_target(self, target):
        return self.request_sync('mining.suggest_target', target)

    def get_speed(self):
        return self.request_sync('client.stats.speed')['result']

    def get_share(self):
        return self.request_sync('client.stats.share')['result']

    def get_balance(self):
        return int(self.request_sync('client.stats.balance')['result'].split()[0])

    def query_flag(self, ranges):
        return self.request_sync('client.exchange.flag', ranges)['result']

    def loop(self):
        try:
            while True:
                o = self.process_one()
                id_ = o.get('id')
                if id_ is not None and id_ in self.slots:
                    self.slots[id_] = o
                log.debug('got object: %r', o)
        except EOFError as e:
            log.warning('invalid json: %r', e)

    def try_solve(self):
        cur_job = self.job
        hdr = cur_job['header'].decode('hex') + struct.pack('<I',
                self.nonce1 + cur_job['id'])
        self.nonce2 += 1
        h = job_hash(hdr, self.nonce2, cur_job['time'])
        d = int(h, 16)
        if d < self.target:
            cur_target = self.target
            log.info('good nonce: %#x %s %d', self.nonce2, h, (1 << 256) / d)
            res = self.submit(struct.pack('>I', self.nonce2).encode('hex'),
                    cur_job['time'], cur_job['id'])
            if res.get('result') == False:
                # wait for syncing current job
                time.sleep(1)
                if self.job != cur_job:
                    log.warn('late submission')
                    return False
                else:
                    log.error('invalid response: %r', res)
                    raise CheckFailure('share not accepted: %r' % res)
            self.expected_share += ((1 << 256) - 1) / cur_target
            return True
        return False

if __name__ == '__main__':
    context.log_level = 'DEBUG'
    p = process(['./poool'])
    s = Stratum(p)
    s.login()
    p.interactive()
