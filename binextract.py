#!/usr/bin/python3

import argparse
from elf import Elf

fmts = [Elf]

def id_file(fname):
    '''
    Check for supported file signature and return the matching class.

    TODO: require base fmt class for unsupported files
    '''
    return [fmt(fname) for fmt in fmts if fmt(fname).signature()][0]


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--fname", help="FileName")
    parser.add_argument("-l", "--header", help="List file header", action="store_true")
    parser.add_argument("-S", "--section_header", help="Section header", action="store_true")
    parser.add_argument("-s", "--shellcode_file", help="Shellcode output")

    args = parser.parse_args()

    if args.fname == None:
        parser.print_help()
        exit(1)

    fmt = id_file(args.fname)

    if fmt == None:
        exit(1)

    fmt.file_header()
    fmt.section_headers()

    if args.header:
        fmt.print_file_header()

    if args.section_header:
        fmt.print_section_headers()

    if args.shellcode_file:
        fmt.shellcode(args.shellcode_file)
