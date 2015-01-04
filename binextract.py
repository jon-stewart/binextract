#!/usr/bin/python3

import argparse

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--header", help="List file header", action="store_true")
    parser.add_argument("-s", "--shellcode_file", help="Shellcode output")

    args = parser.parse_args()

    if args.header:
        pass
