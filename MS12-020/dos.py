# dos.py

import argparse
import sys
import socket

parser = argparse.ArgumentParser()
parser.add_argument('--ip', description='Remote IP')
parser.add_argument('--port', description='Remote port')
parser.add_argument('--check')
parser.add_argument('--dos')
args = parser.parse_args()

'''
Check MS12-020 vulnerability on the remote machine
'''
def do_check(ip: str, port: int):
    print(f'[*] Checking {ip}:{port} for MS12-020 vulnerability...')

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((ip, port))

        req = b'\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00'
        sock.sendall(req)
        resp = sock.recv(1024)

        if not resp or not resp.startswith(b'\x03\x00\x00\x0b\x06\xd0'):
            print(f'[-] Target did not return a valid RDP connection confiromation')
            sock.close()
            return False

        init = (
            
        )
        
    except Exception as ex:
        print(ex)

'''
Crash remote machine via MS12-020
'''
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