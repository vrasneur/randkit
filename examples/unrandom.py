#!/usr/bin/env python

import os
import struct
import subprocess
import sys

class Xor128(object):
    MASK = 2**32 - 1

    def __init__(self, x=123456789, y=362436069, z=521288629, w=88675123):
        self.x = x
        self.y = y
        self.z = z
        self.w = w

    @classmethod
    def init_from_urandom(cls):
        rnd = os.urandom(16)
        x = struct.unpack('<L', rnd[0:4])[0]
        y = struct.unpack('<L', rnd[4:8])[0]
        z = struct.unpack('<L', rnd[8:12])[0]
        w = struct.unpack('<L', rnd[12:16])[0]
        
        return cls(x=x, y=y, z=z, w=w)
        
    @classmethod
    def reverse_xor_lshift(cls, y, shift):
        x = y
        idx = shift

        while idx < 32:
            x ^= x << idx
            idx <<= 1

        return x & cls.MASK

    @classmethod
    def reverse_xor_rshift(cls, y, shift):
        x = y
        idx = shift

        while idx < 32:
            x ^= x >> idx
            idx <<= 1

        return x & cls.MASK

    def forward(self):
        t = self.x ^ self.x << 11
        t &= self.MASK
        self.x = self.y
        self.y = self.z
        self.z = self.w

        self.w = (self.w ^ (self.w >> 19)) ^ (t ^ (t >> 8))
        self.w &= self.MASK

        return self.w

    def backward(self):
        tmp = self.w ^ self.z ^ (self.z >> 19)
        t = self.reverse_xor_rshift(tmp, 8)

        self.w = self.z
        self.z = self.y
        self.y = self.x
        self.x = self.reverse_xor_lshift(t, 11)

        return self.w

    def print_state(self):
        print 'x=%d\ny=%d\nz=%d\nw=%d\n' % (self.x, self.y, self.z, self.w)

    def output_state(self):
        return struct.pack('<LLLL', self.x, self.y, self.z, self.w)

    def gpg_decrypt(self, infile, outfile):
        ret = 2
        idx = 1

        while ret != 0:
            print '[*] iteration: %d' % idx
            p = subprocess.Popen('gpg -q --decrypt --passphrase-fd 0 --output %s %s' % (outfile, infile),
                                 shell=True, stdin=subprocess.PIPE)
            p.communicate(input=self.output_state())
            ret = p.returncode
            if ret == 0:
                print '[*] key found!'
            else:
                print '[*] bad key. Retrying with previous state...'
                self.backward()
                idx += 1
        
if __name__ == '__main__':
    if len(sys.argv) != 3:
        print >>sys.stderr, '[!] syntax: %s <encrypted_file_path> <decryted_file_path>' % sys.argv[0]
        raise SystemExit(-1)
    
    p = Xor128.init_from_urandom()
    p.gpg_decrypt(sys.argv[1], sys.argv[2])
