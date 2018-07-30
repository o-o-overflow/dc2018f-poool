from pwn import *
import json, string, threading

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
    log.warning('no valid target: %r', o)

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
    log.warning('no valid job: %r', o)

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
        self.target = 0
        self.job = None

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
            return {}
        return o

    def process_one(self):
        o = self._process_one()
        method = o.get('method')
        if method in self.handlers:
            self.handlers[method](self, o)
        return o

    def request_sync(self, method, params=[]):
        self.id += 1
        id_ = self.id
        self.slots[id_] = None
        self.tube.sendline(json.dumps({
            'id': id_,
            'method': method,
            'params': params
            }))
        while self.slots[id_] is None:
            time.sleep(0.1)
        return self.slots[id_]

    def login(self):
        self.nonce1 = int(self.request_sync('mining.subscribe', [])['result'][1], 16)
        self.request_sync('mining.authorize', [self.username, 'x'])
        log.info('nonce1 = %08x', self.nonce1)

    def submit(self, nonce2, time=None):
        if time is None:
            time = self.job['time']
        return self.request_sync('mining.submit', [self.username, self.job['id'],
            nonce2, '%08x' % time])

    def set_target(self, target):
        return self.request_sync('mining.suggest_target', target)

    def get_speed(self):
        return self.request_sync('client.stats.speed')['result']

    def get_share(self):
        return self.request_sync('client.stats.share')['result']

    def get_balance(self):
        return self.request_sync('client.stats.balance')['result']

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

if __name__ == '__main__':
    context.log_level = 'DEBUG'
    p = process(['./poool'])
    s = Stratum(p)
    s.login()
    p.interactive()
