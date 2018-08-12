from pwn import *
import os, random

if os.environ.get('NUM'):
    num = int(os.environ['NUM']) - 1
else:
    num = random.randint(0, 3)

POOOL = [
        '35.226.104.167',
        '35.225.200.130',
        '104.154.190.90',
        '35.193.7.153',
        ][num]

POWER = None

USER = 'poool'
PASSWORD = '1f2e0442ba4c32c9' # ;)
CALC = '/home/poool/calc'

def superhash(hdr, diff, threads=4, timeout=5):
    global POWER
    if POWER is None:
        POWER = ssh(host=POOOL, user=USER, password=PASSWORD)
    cmd = [CALC, str(hdr), str(diff), str(threads), str(timeout)]
    p = POWER.process(cmd)
    return filter(lambda _:_, p.readall().split('\n'))
