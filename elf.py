#!/usr/bin/python3

from collections import OrderedDict
import struct

e_fields  = ["e_ident_mag", "e_ident_class", "e_ident_data", "e_ident_version",
             "e_ident_osabi", "e_ident_abiversion", "e_type", "e_machine",
             "e_version", "e_entry", "e_phoff", "e_shoff", "e_flags", "e_ehsize",
             "e_phentsize", "e_phnum", "e_shentsize", "e_shnum", "e_shstrndx"]
sh_fields = ["sh_name", "sh_type", "sh_flags", "sh_addr", "sh_offset",
             "sh_size", "sh_link", "sh_info", "sh_addralign", "sh_entsize"]

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


    def file_header(self):
        '''
        Extract the elf file header.

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
        for k,v in enumerate(e_fields):
            hdr[v] = hdr_raw[k]

        # setting the following to meaningful values
        hdr["e_ident_class"] = e_ident_class[hdr["e_ident_class"]]
        hdr["e_ident_data"]  = e_ident_data[hdr["e_ident_data"]]
        hdr["e_ident_osabi"] = e_ident_osabi[hdr["e_ident_osabi"]]
        hdr["e_type"]        = e_type[hdr["e_type"]]
        hdr["e_machine"]     = e_machine[hdr["e_machine"]]

        self.hdr = hdr


    def section_headers(self):
        '''
        Extract the section header information.

        e_shstrndx is the index of the shstrtab which contains the string
        table of section header names.

        Assign each of these names to the appropriate section header.  The
        first string is the shstrtab, the rest assigned in order.
        '''
        if self.hdr["e_ident_data"] == "x86":
            sh_fmt = "IIIIIIIIII"
        else:
            sh_fmt = "IIQQQQIIQQ"

        sh_off  = self.hdr["e_shoff"]
        sh_size = self.hdr["e_shentsize"]
        sh_num  = self.hdr["e_shnum"]

        sh_hdrs = []

        for i in range(0, sh_num):
            sh_hdr = struct.unpack(sh_fmt, self.data[sh_off:sh_off + sh_size])
            sh_off += sh_size

            sh_dict = OrderedDict()
            for k,v in enumerate(sh_fields):
                sh_dict[v] = sh_hdr[k]

            sh_hdrs.append(sh_dict)

        stridx   = self.hdr["e_shstrndx"]
        shstrtab = sh_hdrs[stridx]

        offset = shstrtab["sh_offset"]
        size   = shstrtab["sh_size"]
        strtab = self.data[offset:offset + size]

        # each string is divided by a NULL byte, need to remove the junk from list
        strtab = [ s for s in strtab.decode().split("\x00") if len(s) > 0]

        for k,v in enumerate(strtab):
            # first string is the .shstrtab, assign to correct index
            if k == 0:
                sh_hdrs[stridx]["sh_name"] = v
            else:
                sh_hdrs[k]["sh_name"] = v

        self.sh_hdrs = sh_hdrs


    def shellcode(self):
        '''
        Extract the .text section from the elf.

        The code is printed to the screen in typical shellcode format that can
        be copy and pasted.

        Write code out to file in binary format so it can be read and used by
        other programs.
        '''
        for section in self.sh_hdrs:
            if section["sh_name"] == ".text":
                offset = section["sh_offset"]
                size   = section["sh_size"]
                chunk  = self.data[offset:offset + size]

                c_fmt  = "%dB" % size
                code   = struct.unpack(c_fmt, chunk)

                shellcode = ""
                for i in code:
                    if i < 0xf:
                        shellcode += "\\x0%x" % i
                    else:
                        shellcode += "\\x%x" % i

                print("Shellcode:")
                print(shellcode, "\n")

                try:
                    with open("/tmp/output.sc", "wb") as fp:
                        fp.write(chunk)
                        print("Shellcode written to /tmp/output.sc")
                except:
                    print("[!] Cannot open file to write")



if __name__ == "__main__":
    elf = Elf("ls.jon")

    elf.signature()
    elf.file_header()
    elf.section_headers()
    elf.shellcode()
