#!/usr/bin/python3

from collections import namedtuple
import struct

e_class    = namedtuple("e_class", ["x86", "x86_64"])
endian     = namedtuple("endian", ["little", "big"])

class Elf(object):

    def __init__(self, fname):

        self.data = self.read_binary(fname)


    def read_binary(self, fname):
        data = None

        try:
            with open(fname, "rb") as fp:
                data = fp.read()
        except:
            print("[!] file %s not found\n" % fname)

        return data


    def signature(self):
        '''
        Extract and test file signature to verify that this is indeed an ELF file.
        '''
        fmt = ">4s"
        sig = struct.unpack(fmt, self.data[0:4])[0]

        return sig.decode() == "\x7fELF"


    def header(self):
        pass


if __name__ == "__main__":
    elf = Elf("ls.jon")
