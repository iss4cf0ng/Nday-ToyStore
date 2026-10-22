# dos.py

import argparse
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--ip')
parser.add_argument('--port')
parser.add_argument('--check')
parser.add_argument('--dos')
args = parser.parse_args()

def do_check(ip: str, port: int):
    pass

def do_dos(ip: str, port: int):
    pass

def main():
    if not (args.ip and args.port):
        parser.print_help()
        sys.exit(1)

    ip = args.ip
    port = int(args.port)

    if args.check:
        do_check(ip, port)
    elif args.dos:
        do_dos(ip, port)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()