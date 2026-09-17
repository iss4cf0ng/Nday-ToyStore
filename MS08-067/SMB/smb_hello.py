# smb_hello.py

import socket
import sys

def main():
    if len(sys.argv) < 2:
        print(f'Usage: python3 {sys.argv[0]} <target ip>')
        return

    target_ip = sys.argv[1]
    target_port = 445

    print(f'[*] Connecting to {target_ip}:{target_port}')

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        sock.connect((target_ip, target_port))
        print('[+] TCP connected successfully')
    except Exception as ex:
        print(f'[-] Connection failed: {ex}')
        return

    netbios_header = b'\x00\x00\x00\x2f'
    smb_header = (
        b'\xff\x53\x4d\x42'  # Protocol Name: \xffSMB
        b'\x72'              # Command: SMB_COM_NEGOTIATE
        b'\x00\x00\x00\x00'  # Status (NT Status)
        b'\x18'              # Flags
        b'\x53\xc8'          # Flags2
        b'\x00\x00'          # PID High
        b'\x00\x00\x00\x00\x00\x00\x00\x00' # Signature (8 bytes)
        b'\x00\x00'          # Reserved
        b'\xfe\xca'          # TID (Tree ID)
        b'\x00\x00'          # PID (Process ID)
        b'\x00\x00'          # UID (User ID)
        b'\x00\x00'          # MID (Multiplex ID)
    )

    smb_data = (
        b'\x00'
        b'\x0c\x00'
        b'\x02'
        b'NT LM 0.12\x00'
    )

    packet = netbios_header + smb_header + smb_data

    print('[*] Sending SMB Negotiate Request...')

    sock.sendall(packet)
    resp = sock.recv(1024)

    print(f'[+] Received {len(resp)} bytes from target')
    print(f'[+] Hex response: {resp.hex()}')

    sock.close()

if __name__ == '__main__':
    main()