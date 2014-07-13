#!/usr/bin/python

import sys
import struct
import operator

options         = ["-h", "-s"]

elf_class       = ["", "x86", "x86_64"]
elf_endian      = ["", "little", "big"]
elf_tgt_sys     = ["system v", "hp-ux", "netBSD", "linux", "solaris", "aix",
                    "irix", "freeBSD", "openBSD"]
elf_type        = ["", "rel", "exe", "shrd", "core"]
elf_inst_arch   = {0x2:"SPARC", 0x3:"x86", 0x8:"MIPS", 0x14:"PowerPC",
                    0x28:"ARM", 0x2a:"SuperH", 0x32:"IA-64", 0x3e:"x86-64",
                    0xb7:"AArch64"}

elf_fields      = ["e_ident_mag", "e_ident_class", "e_ident_data",
                    "e_ident_version", "e_ident_osabi", "e_ident_abiversion",
                    "e_type", "e_machine", "e_version", "e_entry", "e_phoff",
                    "e_shoff", "e_flags", "e_ehsize", "e_phentsize", "e_phnum",
                    "e_shentsize", "e_shnum", "e_shstrndx"]

elf_names       = ["magic", "class", "endian", "orig elf", "system", "abi ver",
                    "type", "arch", "ver", "entry point", "prog header",
                    "section header", "flags", "header size",
                    "prog header size", "number of prog headers",
                    "section header size", "number of section headers",
                    "section header str tbl idx"]

sh_names        = ["sh_name", "sh_type", "sh_flags", "sh_addr", "sh_offset",
                    "sh_size", "sh_link", "sh_info", "sh_addralign",
                    "sh_entsize"]

def read_binary(fname):
    '''
    '''
    data = None

    try:
        with open(fname, "rb") as fp:
            data = fp.read()
    except:
        print("[!] file %s not found\n" % fname)

    return data


def disassemble_elf_header(data):
    '''
    '''
    # TODO: e_entr, e_phoff, e_shoff are 8byte if 64bit file
    elf_hdr_fmt = "4sBBBBB7sHHIIIIIHHHHHH"
    elf_hdr = list(struct.unpack(elf_hdr_fmt, data[0:0x34]))

    # remove the unused e_ident[EI_PAD]
    del elf_hdr[6]

    elf_dict = {}
    for i,field in enumerate(elf_fields):
        elf_dict[field] = [i, elf_names[i], elf_hdr[i]]

    # set class
    elf_dict["e_ident_class"][2] = elf_class[elf_dict["e_ident_class"][2]]
    # set endian
    elf_dict["e_ident_data"][2] = elf_endian[elf_dict["e_ident_data"][2]]
    # set target system
    elf_dict["e_ident_osabi"][2] = elf_tgt_sys[elf_dict["e_ident_osabi"][2]]
    # set object type
    elf_dict["e_type"][2] = elf_type[elf_dict["e_type"][2]]
    # set target instruction set arch
    elf_dict["e_machine"][2] = elf_inst_arch[elf_dict["e_machine"][2]]

    return elf_dict


def disassemble_elf_code(data, sh_off, sh_size, sh_num):
    '''
    '''
    sh_fmt = "IIIIIIIIII"

    for i in range(0, sh_num):
        sh_hdr = struct.unpack(sh_fmt, data[sh_off:sh_off + sh_size])
        sh_off += sh_size

        sh_dict = {}
        for k,v in enumerate(sh_names):
            sh_dict[v] = sh_hdr[k]

        # if SHT_PROGBITS
        if (sh_dict["sh_type"] == 1):
            code_addr = sh_dict["sh_offset"]
            code_size = sh_dict["sh_size"]
            code_chunk = data[code_addr:code_addr + code_size]

            code_fmt = "%dB" % code_size
            code = (struct.unpack(code_fmt, code_chunk))
            for i in code:
                print("%x" % i)


def disassemble_elf(fname, opt):
    '''
    '''
    data = read_binary(fname)
    if (data is None):
        return

    elf_dict = disassemble_elf_header(data)

    if opt == "-h":
        print("\nDisas elf header\n")
        sorted_dict = sorted(elf_dict.items(), key=operator.itemgetter(1))
        for entry in sorted_dict:
            v = entry[1]
            print("\t%s: %s" % (v[1], v[2]))

    elif opt == "-s":
        sh_off  = elf_dict["e_shoff"][2]
        sh_size = elf_dict["e_shentsize"][2]
        sh_num  =  elf_dict["e_shnum"][2]
        disassemble_elf_code(data, sh_off, sh_size, sh_num)


def help_text():
    print("Usage:\n\t%s <elf path>\n" % sys.argv[0])
    print("\t-h\toutput header")
    print("\t-s\toutput shellcode")


opt = [o for o in options if o in sys.argv]
fname = [arg for arg in sys.argv if arg not in options and arg != sys.argv[0]]

if (len(opt) > 1) or (len(fname) != 1):
    help_text()
else:
    disassemble_elf(fname[0], opt[0])
