#!/usr/bin/env python

import argparse

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('input_file',
        help='''file containing 60-character lines of text, one of which is
        encrypted with one-character XOR''')
args = arg_parser.parse_args()

def main():
    pass

if __name__ == "__main__":
    main()
