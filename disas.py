#!/usr/bin/python

import sys
import struct

options         = ["-h", "-s"]

elf_class       = ["", "x86", "x86_64"]
elf_endian      = ["", "little", "big"]
elf_tgt_sys     = ["system v", "hp-ux", "netBSD", "linux", "solaris", "aix",
                    "irix", "freeBSD", "openBSD"]
elf_type        = ["", "rel", "exe", "shrd", "core"]
elf_inst_arch   = {0x2:"SPARC", 0x3:"x86", 0x8:"MIPS", 0x14:"PowerPC",
                    0x28:"ARM", 0x2a:"SuperH", 0x32:"IA-64", 0x3e:"x86-64",
                    0xb7:"AArch64"}

elf_names       = ["magic", "class", "endian", "orig elf", "system", "abi ver",
                    "type", "arch", "ver", "entry point", "prog header",
                    "section header", "flags", "header size",
                    "prog header size", "number of prog headers",
                    "section header size", "number of section headers",
                    "section header str tbl idx"]


def help_text():
    print("Usage:\n\t%s <elf path>\n" % sys.argv[0])
    print("\t-h\toutput header")
    print("\t-s\toutput shellcode")

def disas_elf(fname, opt):
    '''
    '''
    data = None

    try:
        with open(fname, "rb") as fp:
            lines = fp.readlines()
            data = lines[0]
    except:
        print("[!] file %s not found\n" % fname)

    # TODO: e_entr, e_phoff, e_shoff are 8byte if 64bit file
    elf_hdr_fmt = "4sBBBBB7sHHIIIIIHHHHHH"
    elf_hdr = list(struct.unpack(elf_hdr_fmt, data[0:0x34]))

    # remove the unused e_ident[EI_PAD]
    del elf_hdr[6]
    # set class
    elf_hdr[1] = elf_class[elf_hdr[1]]
    # set endian
    elf_hdr[2] = elf_endian[elf_hdr[2]]
    # set target system
    elf_hdr[4] = elf_tgt_sys[elf_hdr[4]]
    # set object type
    elf_hdr[6] = elf_type[elf_hdr[6]]
    # set target instruction set arch
    elf_hdr[7] = elf_inst_arch[elf_hdr[7]]

    if opt == "-h":
        print("\nDisas elf header\n")
        for k,v in enumerate(elf_names):
            print("\t%s: %s" % (v, elf_hdr[k]))
    elif opt == "-s":
        pass
#        (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link,
#            sh_info, sh_addralign, sh_entsize) = struct.unpack("IIIIIIIIII", data[offset:offset + ])


opt = [o for o in options if o in sys.argv]
fname = [arg for arg in sys.argv if arg not in options and arg != sys.argv[0]]

if (len(opt) > 1) or (len(fname) != 1):
    help_text()
else:
    disas_elf(fname[0], opt[0])
