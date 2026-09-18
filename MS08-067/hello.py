# hello.py

import sys
from impacket import uuid
from impacket.dcerpc.v5 import transport

def main():
    if len(sys.argv) < 3:
        print(f'\nUsage: {sys.argv[0]} <ip> <port>\n')
        return

    ip = sys.argv[1]
    port = int(sys.argv[2])

    if port == 445:
        trans = transport.DCERPCTransportFactory(f'ncacn_np:{ip}[\\pipe\\browser]')
    else:
        trans = transport.SMBTransport(remoteName='*SMBSERVER', remote_host=ip, dstport=port, filename='\\browser')

    trans.connect()

    print('[+] Connected successfully')

    dce = trans.DCERPC_class(trans)
    dce.bind(uuid.uuidtup_to_bin(('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0')))

    print('[+] Successfully binded DCE/RPC interface')

if __name__ == '__main__':
    main()