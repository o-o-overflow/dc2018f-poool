import ctypes, hashlib, struct

cn = ctypes.CDLL('./libcryptonight.so')

_cryptonight = cn.cryptonight
_cryptonight.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p)

_buffer = ctypes.c_buffer(32)

def cryptonight(s):
    _cryptonight(s, len(s), ctypes.byref(_buffer))
    return _buffer.raw

def ooohash(s):
    return hashlib.sha256(cryptonight(s)).hexdigest()

def job_hash(header, nonce2, timestamp):
    return ooohash(header + struct.pack('<II', timestamp, nonce2) + '\x00\x4f\x6f\x30')

if __name__ == '__main__':
    assert cryptonight('').encode('hex') == 'eb14e8a833fac6fe9a43b57b336789c46ffe93f2868452240720607b14387e11'
    assert cryptonight('This is a test').encode('hex') == 'a084f01d1437a09c6985401b60d43554ae105802c5f5d8a9b3253649c0be6605'
