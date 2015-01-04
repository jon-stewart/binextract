#!/usr/bin/python3

from collections import OrderedDict
import struct

fields = ["e_ident_mag", "e_ident_class", "e_ident_data", "e_ident_version",
          "e_ident_osabi", "e_ident_abiversion", "e_type", "e_machine",
          "e_version", "e_entry", "e_phoff", "e_shoff", "e_flags", "e_ehsize",
          "e_phentsize", "e_phnum", "e_shentsize", "e_shnum", "e_shstrndx"]

e_ident_class = ["", "x86", "x86_64"]
e_ident_data  = ["", "little", "big"]
e_ident_osabi = ["system v", "hp-ux", "netBSD", "linux", "solaris", "aix",
                 "irix", "freeBSD", "openBSD"]
e_type        = ["", "REL", "EXE", "SHRD", "CORE"]
e_machine     = {0x2:"SPARC", 0x3:"x86", 0x8:"MIPS", 0x14:"PowerPC",
                 0x28:"ARM", 0x2a:"SuperH", 0x32:"IA-64", 0x3e:"x86-64",
                 0xb7:"AArch64"}


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
        Extract and test file signature to verify that this is indeed an elf file.
        '''
        fmt   = ">4s"
        magic = "\x7fELF"
        sig   = struct.unpack(fmt, self.data[0:4])[0]

        return sig.decode() == magic


    def header(self):
        '''
        Extract elf header.

        Set format and length based on 32/64bit field, extract and place in
        OrderedDict with associated field name for easy/clear access.
        '''
        arch = struct.unpack("B", self.data[4:5])[0]

        if arch == 1:
            # 32bit
            hdr_fmt = "4sBBBBB7sHHIIIIIHHHHHH"
            hdr_len = 0x34
        elif arch == 2:
            # 64bit: e_entry, e_phoff and e_shoff are 8bytes in size
            hdr_fmt = "4sBBBBB7sHHIQQQIHHHHHH"
            hdr_len = 0x40

        hdr_raw = list(struct.unpack(hdr_fmt, self.data[:hdr_len]))

        # remove e_ident[EI_PAD]
        del hdr_raw[6]

        hdr = OrderedDict()
        for i,field in enumerate(fields):
            hdr[field] = hdr_raw[i]

        hdr["e_ident_class"] = e_ident_class[hdr["e_ident_class"]]
        hdr["e_ident_data"]  = e_ident_data[hdr["e_ident_data"]]
        hdr["e_ident_osabi"] = e_ident_osabi[hdr["e_ident_osabi"]]
        hdr["e_type"]        = e_type[hdr["e_type"]]
        hdr["e_machine"]     = e_machine[hdr["e_machine"]]


if __name__ == "__main__":
    elf = Elf("ls.jon")

    elf.signature()
    elf.header()
