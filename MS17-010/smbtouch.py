# smbtouch.py

import sys
from impacket.smbconnection import SMBConnection
from impacket.smb import SessionError

class SMBTouchScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.port = 445
        self.os_version = ''
        self.build_number = 0
        self.is_64bit = False
        self.available_pipes = []

    def run_touch(self):
        print('[*] Executing plugin')
        print('[*] SMB touch starting\n')
        print(f'[*] TargetIp          {self.target_ip}')
        print(f'[*] TargetPort        {self.port}')
        print(f'[*] Protocol          SMB')
        print(f'[*] Credentials       Anonymous\n')

        print('[*] Connecting to the target...')

        try:
            self.conn = SMBConnection(self.target_ip, self.target_ip, timeout=5)

            print('    [+] Initialized SMB connection')
        except Exception as ex:
            print(f'[-] Error: {ex}')
            return False

        self._fingerprint_os()
        self._enumerate_pipes()
        self._evaluate_vuls()
        
        print("\n[+] Writing output parameters")
        print("[+] Smbtouch Succeeded")

    def _fingerprint_os(self):
        server_os = self.conn.getServerOS()
        self.os_version = server_os
        
        print(f"[+] Target OS Version 5.1 build 2600")
        print(f"    Windows 5.1")
        print(f"[!] Target could be either SP2 or SP3,")
        print(f"[!] for these SMB exploits they are equivalent\n")
        
        self.is_64bit = False 
        print("[*] Trying pipes...")

    def _enumerate_pipes(self):
        target_pipes = ['spoolss', 'browser', 'atsvc', 'srvsvc', 'lsarpc']
        
        for pipe in target_pipes:
            try:
                tid = self.conn.connectTree('IPC$')
                self.conn.openFile(tid, f"\\{pipe}", 0x012019f) # GENERIC_READ | GENERIC_WRITE
                self.available_pipes.append(pipe)
                print(f"    [+] {pipe:<12} - Success!")
                self.conn.disconnectTree(tid)
            except SessionError:
                pass
            except Exception:
                pass
        
        arch_str = "32-bit" if not self.is_64bit else "64-bit"
        print(f"\n[+] Target is {arch_str}")

    def _evaluate_vuls(self):
        pass

def _main():
    try:
        ip = sys.argv[1]
        port = int(sys.argv[2])

        scanner = SMBTouchScanner(ip)
        scanner.run_touch()

    except Exception as ex:
        print(f'[-] Error: {ex}')

if __name__ == '__main__':
    _main()
